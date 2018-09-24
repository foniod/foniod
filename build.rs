extern crate failure;
extern crate redbpf;

use failure::Error;
use std::env;
use std::io;
use std::ffi::OsString;
use std::fs::read_dir;
use std::path::PathBuf;

use redbpf::build::{build, generate_bindings, cache::BuildCache, headers::headers};

fn main() -> Result<(), Error> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let headers = headers().unwrap();
    let flags = {
        let mut cflags: Vec<OsString> = redbpf::build::BUILD_FLAGS
            .iter()
            .map(OsString::from)
            .collect();

        cflags.append(&mut headers.clone());
        cflags
    };
    let bindgen_flags: Vec<String> = flags
        .iter()
        .cloned()
        .map(|f| f.into_string().unwrap())
        .collect();

    let mut cache = BuildCache::new(&out_dir);

    for file in source_files("./bpf", "c")? {
        if cache.file_changed(&file) {
            build(&flags[..], &out_dir, &file).expect("Failed building BPF plugin!");
        }
    }
    for file in source_files("./bpf", "h")? {
        if cache.file_changed(&file) {
            generate_bindings(&bindgen_flags[..], &out_dir, &file)
                .expect("Failed generating data bindings!");
        }
    }

    cache.save();
    Ok(())
}

fn source_files(
    dir: &'static str,
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
                }).is_some()
        }))
}
