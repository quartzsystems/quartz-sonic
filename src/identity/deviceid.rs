//! Device ID derivation — a pure function of the Ed25519 public key.
//!
//! `"QS-" + Crockford base32(SHA256(pubkey_raw))[0:16]`, formatted in groups
//! of four (`QS-XXXX-XXXX-XXXX-XXXX`). This is a verbatim port of the
//! QuartzCommand server's `backend/src/pki/deviceid.rs` (with the SONiC
//! product-line prefix); enrollment verifies the device's claimed ID against
//! the server's own derivation from the pubkey and the token's product line,
//! so the two implementations must never drift — the fixed vectors below pin
//! ours.

use sha2::{Digest, Sha256};

/// Crockford base32 alphabet (no I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Standard MSB-first base32 over the Crockford alphabet, `n` output chars.
fn crockford_prefix(data: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 0x1f) as usize] as char);
            if out.len() == n {
                return out;
            }
        }
    }
    // Zero-pad any trailing partial group (standard base32 behavior; never
    // reached for the 16-char prefix of a 32-byte digest).
    if bits > 0 && out.len() < n {
        out.push(CROCKFORD[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Derive the canonical device ID from a raw 32-byte Ed25519 public key.
pub fn derive_device_id(pubkey_raw: &[u8]) -> String {
    let digest = Sha256::digest(pubkey_raw);
    let chars = crockford_prefix(&digest, 16);
    let groups: Vec<&str> = chars
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect();
    format!("QS-{}", groups.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed pubkey → ID vectors. These pin the derivation against silent
    /// change: SHA-256 choice, Crockford alphabet, MSB-first bit order,
    /// 16-char truncation, grouping, and the QS product-line prefix are all
    /// load-bearing wire format (the server derives the same string and
    /// rejects mismatches). The base32 characters match qfagent's vectors —
    /// the digest is over the pubkey only; the prefix is the product line.
    #[test]
    fn fixed_vectors() {
        // 32 zero bytes.
        let zero = [0u8; 32];
        // 0x01, 0x02, … 0x20.
        let seq: Vec<u8> = (1u8..=32).collect();
        // The RFC 8032 TEST 1 public key.
        let rfc8032 = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

        assert_eq!(derive_device_id(&zero), "QS-CSM7-NBFR-CAYQ-EV4F");
        assert_eq!(derive_device_id(&seq), "QS-NRGP-RBQN-4HX3-F0P1");
        assert_eq!(derive_device_id(&rfc8032), "QS-47Z3-3QX1-AJH6-2RKB");
    }

    #[test]
    fn shape_and_alphabet() {
        let id = derive_device_id(&[7u8; 32]);
        assert!(id.starts_with("QS-"));
        assert_eq!(id.len(), 3 + 16 + 3); // QS- + 16 chars + 3 inner dashes
        assert_eq!(id.split('-').count(), 5);
        for c in id.chars() {
            assert!(!"ILOU".contains(c), "excluded Crockford char {c} in {id}");
        }
    }

    #[test]
    fn stable_and_key_dependent() {
        assert_eq!(derive_device_id(&[1u8; 32]), derive_device_id(&[1u8; 32]));
        assert_ne!(derive_device_id(&[1u8; 32]), derive_device_id(&[2u8; 32]));
    }

    /// Same primitive vectors as the server's own tests.
    #[test]
    fn crockford_known_vector() {
        // 0xFF -> bits 11111 111(00) -> "Z" then "W" (11100).
        assert_eq!(crockford_prefix(&[0xff], 2), "ZW");
        assert_eq!(crockford_prefix(&[0x00], 1), "0");
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
