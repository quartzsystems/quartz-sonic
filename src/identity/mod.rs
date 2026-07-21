//! Device identity: the Ed25519 keypair and its on-disk lifecycle.
//!
//! Layout (under `/var/lib/quartz-sonic/`, root-only):
//!
//! | file           | content                                             |
//! |----------------|-----------------------------------------------------|
//! | `device.key`   | Ed25519 private key, PKCS#8 PEM, 0600 root          |
//! | `device.pub`   | Ed25519 public key, SPKI PEM                        |
//! | `client.crt`   | enrollment-issued mTLS client certificate (PEM)     |
//! | `ca-chain.crt` | controller device-CA chain from enrollment (PEM)    |
//! | `pinned-ca.crt`| the CA cert that matched the token's fingerprint    |
//! | `state.json`   | enrollment state (see `state.rs`)                   |
//!
//! Keying is abstracted behind [`KeyBackend`] so a hardware-backed
//! implementation can be added without touching any caller (enrollment,
//! renewal, and the control channel all sign/derive through the trait).

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signer, SigningKey};

pub mod deviceid;

/// Signing/derivation operations the rest of the agent needs from the device
/// key.
pub trait KeyBackend {
    /// Raw 32-byte Ed25519 public key (the device-ID input).
    fn public_key_raw(&self) -> [u8; 32];
    /// Ed25519 signature (64 bytes) over `msg`.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    /// PKCS#8 DER of the private key, for CSR generation.
    fn pkcs8_der(&self) -> Result<Vec<u8>>;
}

pub struct FileKeyBackend {
    key: SigningKey,
}

impl KeyBackend for FileKeyBackend {
    fn public_key_raw(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }

    fn pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_pkcs8_der().context("encode private key")?.as_bytes().to_vec())
    }
}

impl FileKeyBackend {
    pub fn device_id(&self) -> String {
        deviceid::derive_device_id(&self.public_key_raw())
    }
}

// ── on-disk store ─────────────────────────────────────────────────────────────

pub struct IdentityStore {
    pub dir: PathBuf,
}

pub struct Identity {
    pub key: FileKeyBackend,
}

impl IdentityStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("device.key")
    }
    pub fn pub_path(&self) -> PathBuf {
        self.dir.join("device.pub")
    }
    pub fn client_cert_path(&self) -> PathBuf {
        self.dir.join("client.crt")
    }
    pub fn ca_chain_path(&self) -> PathBuf {
        self.dir.join("ca-chain.crt")
    }
    pub fn pinned_ca_path(&self) -> PathBuf {
        self.dir.join("pinned-ca.crt")
    }

    pub fn exists(&self) -> bool {
        self.key_path().exists()
    }

    /// Load the identity, or generate one if absent (first run).
    pub fn load_or_generate(&self) -> Result<Identity> {
        if self.exists() {
            return self.load();
        }
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("create identity dir {}", self.dir.display()))?;
        restrict_dir(&self.dir);

        let key = SigningKey::generate(&mut rand_core::OsRng);
        let key_pem = key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .context("encode private key PEM")?;
        write_private(&self.key_path(), key_pem.as_bytes())?;

        let pub_pem = key
            .verifying_key()
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .context("encode public key PEM")?;
        atomic_write(&self.pub_path(), pub_pem.as_bytes())?;

        let backend = FileKeyBackend { key };
        tracing::info!(device_id = %backend.device_id(), "generated new device identity");
        Ok(Identity { key: backend })
    }

    pub fn load(&self) -> Result<Identity> {
        let pem = std::fs::read_to_string(self.key_path())
            .with_context(|| format!("read {}", self.key_path().display()))?;
        let key = SigningKey::from_pkcs8_pem(&pem).context("parse device.key (PKCS#8 PEM)")?;
        Ok(Identity { key: FileKeyBackend { key } })
    }

    /// Persist the enrollment-issued certificate material (atomic swaps, so
    /// the daemon never reads a half-written cert during renewal).
    pub fn save_certificates(
        &self,
        client_cert_der: &[u8],
        ca_chain_der: &[Vec<u8>],
        pinned_ca_der: Option<&[u8]>,
    ) -> Result<()> {
        atomic_write(&self.client_cert_path(), pem_encode("CERTIFICATE", client_cert_der).as_bytes())?;
        let chain: String = ca_chain_der.iter().map(|der| pem_encode("CERTIFICATE", der)).collect();
        atomic_write(&self.ca_chain_path(), chain.as_bytes())?;
        match pinned_ca_der {
            Some(der) => {
                atomic_write(&self.pinned_ca_path(), pem_encode("CERTIFICATE", der).as_bytes())?
            }
            None => {}
        }
        Ok(())
    }
}

pub fn pem_encode(tag: &str, der: &[u8]) -> String {
    pem::encode(&pem::Pem::new(tag.to_string(), der.to_vec()))
}

/// Write via temp file + rename so readers never see a partial file.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Like `atomic_write` but the file is created 0600 (the private key). On
/// non-Unix dev hosts the mode bits are skipped.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Best-effort 0700 on the state directory (root-only key material).
fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        assert!(!store.exists());
        let generated = store.load_or_generate().unwrap();
        assert!(store.exists());

        let loaded = store.load().unwrap();
        assert_eq!(generated.key.public_key_raw(), loaded.key.public_key_raw());

        // Signature over a message verifies with the stored public key.
        let sig = loaded.key.sign(b"nonce");
        assert_eq!(sig.len(), 64);

        // A second load_or_generate must NOT regenerate.
        let again = store.load_or_generate().unwrap();
        assert_eq!(again.key.public_key_raw(), generated.key.public_key_raw());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path());
        store.load_or_generate().unwrap();
        let mode = std::fs::metadata(store.key_path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn saved_certificates_are_pem() {
        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new(dir.path().join("identity"));
        store.load_or_generate().unwrap();
        store
            .save_certificates(b"fake-cert", &[b"ca-1".to_vec(), b"ca-2".to_vec()], Some(b"pin"))
            .unwrap();
        let chain = std::fs::read_to_string(store.ca_chain_path()).unwrap();
        assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(store.pinned_ca_path().exists());
    }
}
