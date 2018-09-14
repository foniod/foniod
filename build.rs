extern crate bindgen;
extern crate failure;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate redbpf;
extern crate ring;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use failure::{err_msg, Error};
use regex::Regex;
use ring::digest;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, read_dir, File};
use std::path::{Path, PathBuf};
use std::process::Command;

fn compile_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.obj", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

fn final_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.elf", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

fn build(flags: &[OsString], out_dir: &Path, source: &Path) -> Result<PathBuf, Error> {
    println!("Building eBPF module: {:?} ", source);

    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    let cc_target = compile_target(out_dir, source).unwrap();
    let elf_target = final_target(out_dir, source).unwrap();

    println!("Flags: {:?}", &flags);

    if !Command::new("clang")
        .args(flags)
        .arg("-o")
        .arg(&cc_target)
        .arg(source)
        .status()?
        .success()
    {
        return Err(err_msg("clang failed"));
    }

    if !Command::new("llc")
        .args(&llc_args)
        .arg(&elf_target)
        .arg(&cc_target)
        .status()?
        .success()
    {
        return Err(err_msg("llc failed"));
    }

    Ok(elf_target)
}

fn generate_bindings(flags: &[String], out_dir: &Path, source: &Path) -> Result<(), Error> {
    println!("Building eBPF module: {:?} ", source);
    println!("Flags: {:?}", &flags);

    const TYPE_REGEX: &str = "_data_[^{}]*";
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!(r"struct ({}) \{{", TYPE_REGEX)).unwrap();
    }

    let mut flags = flags.to_vec();
    flags.push("-Wno-unused-function".to_string());

    let bindings = bindgen::builder()
        .header(source.to_str().expect("Filename conversion error!"))
        .clang_args(&flags)
        .whitelist_type(TYPE_REGEX)
        .generate()
        .expect("Unable to generate bindings!");

    let mut code = "".to_owned();

    code.push_str(&bindings.to_string());
    for data_type in RE.captures_iter(&code.clone()) {
        let trait_impl = r"
impl<'a> From<&'a [u8]> for ### {
    fn from(x: &'a [u8]) -> ### {
        unsafe { ptr::read(x.as_ptr() as *const ###) }
    }
}
".replace("###", &data_type[1]);
        code.push_str(&trait_impl);
    }

    let filename = out_dir.join(source.with_extension("rs").file_name().unwrap());
    fs::write(filename, &code)?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let _out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&_out_dir);

    let headers = redbpf::build::headers().unwrap();
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
        .map(|f| f.clone().into_string().unwrap())
        .collect();

    let mut cache = BuildCache::new(&out_dir);

    for file in source_files("./bpf", "c")? {
        if cache.file_changed(&file) {
            build(&flags[..], out_dir, &file).expect("Failed building BPF plugin!");
        }
    }
    for file in source_files("./bpf", "h")? {
        if cache.file_changed(&file) {
            generate_bindings(&bindgen_flags[..], out_dir, &file)
                .expect("Failed generating data bindings!");
        }
    }

    cache.save();

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BuildCache(HashMap<String, Vec<u8>>, PathBuf);

impl BuildCache {
    fn new(dir: &Path) -> BuildCache {
        let file = dir.join(".build_manifest");
        let cache = match File::open(&file)
            .map_err(serde_json::Error::io)
            .and_then(|f| serde_json::from_reader(f))
        {
            Ok(cache) => cache,
            Err(_) => HashMap::new(),
        };

        println!("{:?}", cache);
        BuildCache(cache, file)
    }

    /// Error conditions will return true
    fn file_changed(&mut self, file: &Path) -> bool {
        let fname = match file.to_str() {
            Some(n) => n,
            None => return true
        }.to_string();
        let entry = self.0.entry(fname).or_default();

        let digest = match fs::read(file) {
            Ok(content) => digest::digest(&digest::SHA256, content.as_slice()),
            Err(_) => return true
        };

        let is_match = digest.as_ref() == entry.as_slice();
        *entry = digest.as_ref().to_vec();

        !is_match
    }

    fn save(&self) {
        serde_json::to_writer(File::create(&self.1).unwrap(), &self.0).unwrap();
    }
}

fn source_files(
    dir: &'static str,
    only_extension: &'static str,
) -> ::std::io::Result<impl Iterator<Item = ::std::path::PathBuf>> {
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
