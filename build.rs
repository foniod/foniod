use failure::{bail, Error};
use std::env;
use std::fs::read_dir;
use std::io;
use std::path::{Path, PathBuf};

use redbpf::build::{build, cache::BuildCache, generate_bindings, headers::kernel_headers};
use cargo_bpf_lib as cargo_bpf;

const CAPNP_SCHEMA: &'static str = "schema/ingraind.capnp";

fn main() -> Result<(), Error> {
    let cargo = PathBuf::from(env::var("CARGO")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let kernel_headers = kernel_headers().expect("couldn't find kernel headers");
    let mut bindgen_flags: Vec<String> = kernel_headers
        .iter()
        .map(|dir| format!("-I{}", dir))
        .collect();
    bindgen_flags.extend(redbpf::build::BUILD_FLAGS.iter().map(|f| f.to_string()));

    let mut cache = BuildCache::new(&out_dir);

    for file in source_files("./bpf", "c")? {
        if cache.file_changed(&file) {
            build(&bindgen_flags[..], &out_dir, &file).expect("Failed building BPF plugin!");
        }
    }
    for file in source_files("./bpf", "h")? {
        if cache.file_changed(&file) {
            generate_bindings(&bindgen_flags[..], &out_dir, &file)
                .expect("Failed generating data bindings!");
        }
    }

    let probes = Path::new("ingraind-probes");
    if let Err(e) = cargo_bpf::build(&cargo, &probes, &probes.join("target/release/bpf-programs"), Vec::new()) {
        bail!("couldn't compile ingraind-probes: {}", e);
    }

    build_capnp(&mut cache);

    cache.save();
    Ok(())
}

#[cfg(feature = "capnp-encoding")]
fn build_capnp(cache: &mut BuildCache) {
    if cache.file_changed(Path::new(CAPNP_SCHEMA)) {
        use capnpc::{CompilerCommand, RustEdition};
        CompilerCommand::new()
            .file(CAPNP_SCHEMA)
            .edition(RustEdition::Rust2018)
            .run()
            .expect("capnp schema generation failed");
    }
}

#[cfg(not(feature = "capnp-encoding"))]
fn build_capnp(_: &mut BuildCache) {}

fn source_files<P: AsRef<Path>>(
    dir: P,
    only_extension: &'static str,
) -> io::Result<impl Iterator<Item = PathBuf>> {
    Ok(read_dir(dir)?
        .filter(|entry| entry.is_ok())
        .map(|entry| entry.unwrap().path())
        .filter(move |path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .and_then(|ext| {
                    if ext == only_extension {
                        Some(())
                    } else {
                        None
                    }
                })
                .is_some()
        }))
}
