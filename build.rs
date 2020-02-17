use failure::{bail, Error};
use std::env;
use std::path::{Path, PathBuf};

use cargo_bpf_lib as cargo_bpf;

const CAPNP_SCHEMA: &'static str = "schema/ingraind.capnp";

fn main() -> Result<(), Error> {
    let cargo = PathBuf::from(env::var("CARGO")?);

    let probes = Path::new("ingraind-probes");
    if let Err(e) = cargo_bpf::build(&cargo, &probes, &probes.join("target/release/bpf-programs"), Vec::new()) {
        bail!("couldn't compile ingraind-probes: {}", e);
    }

    build_capnp();

    Ok(())
}

#[cfg(feature = "capnp-encoding")]
fn build_capnp() {
    use capnpc::{CompilerCommand, RustEdition};
    CompilerCommand::new()
        .file(CAPNP_SCHEMA)
        .edition(RustEdition::Rust2018)
        .run()
        .expect("capnp schema generation failed");
}

#[cfg(not(feature = "capnp-encoding"))]
fn build_capnp() {}