//! Compile `proto/validation.proto` into Rust via tonic_build. The
//! generated module is `validation.v1` and lands in `$OUT_DIR/
//! validation.v1.rs` (`include!`-ed by `src/routes/grpc.rs`).
//!
//! Also emit a binary file descriptor set for tonic-reflection so
//! `grpcurl -plaintext localhost:50051 list` works against the
//! running server.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?)
        .join("validation_descriptor.bin");
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/validation.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/validation.proto");
    Ok(())
}
