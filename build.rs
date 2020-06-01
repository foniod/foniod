use std::env;
use std::path::{Path, PathBuf};

use cargo_bpf_lib as cargo_bpf;

const CAPNP_SCHEMA: &'static str = "schema/ingraind.capnp";

fn main() {
    let cargo = PathBuf::from(env::var("CARGO").unwrap());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probes = Path::new("ingraind-probes");
    cargo_bpf::build(
        &cargo,
        &probes,
        &out_dir.join("target"),
        Vec::new(),
    )
    .expect("couldn't compile ingraind-probes");

    build_capnp();

    cargo_bpf::probe_files(&probes)
        .expect("couldn't list probe files")
        .iter()
        .for_each(|file| {
            println!("cargo:rerun-if-changed={}", file);
        });
}

#[cfg(feature = "capnp-encoding")]
fn build_capnp() {
    use capnpc::CompilerCommand;
    CompilerCommand::new()
        .file(CAPNP_SCHEMA)
        .run()
        .expect("capnp schema generation failed");
}

#[cfg(not(feature = "capnp-encoding"))]
fn build_capnp() {}
