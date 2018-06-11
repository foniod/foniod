extern crate failure;

use failure::{err_msg, Error};
use std::env;
use std::ffi::OsString;
use std::fs::read_dir;
use std::path::{Path, PathBuf};
use std::process::Command;

fn kernel_headers() -> Result<Vec<OsString>, Error> {
    let uname = Command::new("uname").arg("-r").output()?;
    let release = String::from_utf8(uname.stdout)?.replace("\n", "");

    if release.ends_with("-ARCH") {
        // Support for building on Arch Linux
        let headers_path = format!("/lib/modules/{}/build", release);

        Ok(vec![
            format!("-I{}/arch/x86/include", headers_path).into(),
            format!("-I{}/arch/x86/include/generated", headers_path).into(),
            format!("-I{}/include", headers_path).into(),
            format!("-I{}/arch/include/generated/uapi", headers_path).into(),
            format!("-I{}/arch/x86/include/uapi", headers_path).into(),
            format!("-I{}/include/uapi", headers_path).into(),
            OsString::from("-Ibpf"),
        ])
    } else {
        Err(err_msg(format!("Unsupported kernel version: {}", release)))
    }
}

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

fn build(out_dir: &Path, source: &Path) -> Result<PathBuf, Error> {
    println!("Building eBPF module: {:?} ", source);

    let cc_args = [
        "-D__KERNEL__",
        "-D__ASM_SYSREG_H",
        "-Wno-unused-value",
        "-Wno-pointer-sign",
        "-Wno-compare-distinct-pointer-types",
        "-Wno-unused-parameter",
        "-Wno-missing-field-initializers",
        "-Wno-initializer-overrides",
        "-fno-builtin",
        "-fno-stack-protector",
        "-Wunused",
        "-Wall",
        "-Werror",
        "-O2",
        "-emit-llvm",
        "-c",
        "-o",
    ];

    let llc_args = ["-march=bpf", "-filetype=obj", "-o"];

    let cc_target = compile_target(out_dir, source).unwrap();
    let elf_target = final_target(out_dir, source).unwrap();
    let headers = kernel_headers()?;

    println!("Headers: {:?}", &headers);

    if !Command::new("clang")
        .args(cc_args.iter())
        .arg(&cc_target)
        .arg(source)
        .args(&headers)
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

fn main() -> Result<(), Error> {
    let _out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&_out_dir);

    for file in read_dir("./bpf")?
        .filter(|entry| entry.is_ok())
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .and_then(|ext| if ext == "c" { Some(()) } else { None })
                .is_some()
        }) {
        build(out_dir, &file).expect("Failed building BPF plugin!");
    }

    Ok(())
}
