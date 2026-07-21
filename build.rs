use prost::Message as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The VERSION file at the repo root is the single source of truth for
    // the agent version. It is baked into the binary (env!("QS_VERSION")),
    // and Cargo.toml's [package] version must match it — cargo-deb stamps
    // the .deb from Cargo.toml, so a drift would ship a package whose
    // version disagrees with what the agent reports to the controller.
    let version = std::fs::read_to_string("VERSION")?.trim().to_string();
    if version.is_empty() {
        return Err("VERSION file is empty".into());
    }
    let cargo_version = std::env::var("CARGO_PKG_VERSION")?;
    if version != cargo_version {
        return Err(format!(
            "VERSION file says {version} but Cargo.toml [package] version is {cargo_version} — \
             update Cargo.toml to match VERSION (the source of truth)"
        )
        .into());
    }
    println!("cargo:rustc-env=QS_VERSION={version}");
    println!("cargo:rerun-if-changed=VERSION");

    // Compile the QuartzCommand protos with protox (pure Rust — no protoc
    // binary needed) and generate tonic client stubs. The server side is also
    // generated so tests can run a mock EnrollmentService against the real
    // client code.
    //
    // tonic-build 0.11 has no protox entry point of its own, so the protox
    // descriptor set is handed to prost-build via skip_protoc_run() +
    // file_descriptor_set_path() — prost 0.12's documented protoc-free path.
    let protos = [
        "proto/quartzcommand/enrollment/v1/enrollment.proto",
        "proto/quartzcommand/device/v1/device.proto",
    ];
    let fds = protox::compile(protos, ["proto"])?;
    let fds_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("quartzcommand.fds.bin");
    std::fs::write(&fds_path, fds.encode_to_vec())?;

    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&fds_path).skip_protoc_run();
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(config, &protos, &["proto"])?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
