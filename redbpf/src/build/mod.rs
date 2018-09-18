use regex::Regex;

use std::io;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod cache;
pub mod headers;

pub const BUILD_FLAGS: [&'static str; 16] = [
    "-D__BPF_TRACING__",
    "-D__KERNEL__",
    "-D__ASM_SYSREG_H",
    "-Wno-unused-value",
    "-Wno-pointer-sign",
    "-Wno-compare-distinct-pointer-types",
    "-Wno-unused-parameter",
    "-Wno-missing-field-initializers",
    "-Wno-initializer-overrides",
    "-fno-stack-protector",
    "-Wunused",
    "-Wall",
    "-Werror",
    "-O2",
    "-emit-llvm",
    "-c",
];

#[derive(Debug)]
pub enum Error {
    OSUnsupported,
    KernelHeadersNotFound,
    InvalidOutput,
    Compile,
    Link,
    IO(io::Error)
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(e)
    }
}

fn compile_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.obj", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

fn link_target(out_dir: &Path, source: &Path) -> Option<PathBuf> {
    let basename = source.file_stem()?;
    let target_name = format!("{}.elf", basename.to_str()?);
    Some(out_dir.join(Path::new(&target_name)))
}

pub fn build(flags: &[OsString], out_dir: &Path, source: &Path) -> Result<PathBuf, Error> {
    println!("Building eBPF module: {:?} ", source);

    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];
    let cc_target = compile_target(out_dir, source).unwrap();
    let elf_target = link_target(out_dir, source).unwrap();

    println!("Flags: {:?}", &flags);

    if !Command::new("clang")
        .args(flags)
        .arg("-o")
        .arg(&cc_target)
        .arg(source)
        .status()?
        .success()
    {
        return Err(Error::Compile);
    }

    if !Command::new("llc")
        .args(&llc_args)
        .arg(&elf_target)
        .arg(&cc_target)
        .status()?
        .success()
    {
        return Err(Error::Link);
    }

    Ok(elf_target)
}

pub fn generate_bindings(flags: &[String], out_dir: &Path, source: &Path) -> Result<PathBuf, Error> {
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

    let mut code = bindings.to_string();
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
    fs::write(&filename, &code)?;
    Ok(filename)
}
