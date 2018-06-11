extern crate bindgen;
extern crate failure;
extern crate regex;
#[macro_use]
extern crate lazy_static;

use failure::{err_msg, Error};
use regex::Regex;
use std::env;
use std::ffi::OsString;
use std::fs::{self, read_dir};
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
    const TYPE_REGEX: &str = "_data_.*";
    lazy_static! {
        static ref RE: Regex = Regex::new(&format!("struct \\({}\\)", TYPE_REGEX)).unwrap();
    }

    let bindings = bindgen::builder()
        .header(source.to_str().expect("Filename conversion error!"))
        .clang_args(flags)
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
"
            .replace("###", &data_type[2]);
        code.push_str(&trait_impl);
    }

    let filename = out_dir.join(source.with_extension("rs").file_name().unwrap());
    fs::write(filename, &code)?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let _out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&_out_dir);

    let headers = kernel_headers()?;
    let flags = {
        let mut cflags: Vec<OsString> = vec![
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
        ].iter()
            .map(OsString::from)
            .collect();

        cflags.append(&mut headers.clone());
        cflags
    };
    let bindgen_flags: Vec<String> = flags
        .iter()
        .map(|f| f.clone().into_string().unwrap())
        .collect();

    for file in read_dir("./bpf")?
        .filter(|entry| entry.is_ok())
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .and_then(|ext| if ext == "c" { Some(()) } else { None })
                .is_some()
        }) {
        build(&flags[..], out_dir, &file).expect("Failed building BPF plugin!");

        let data_header = file.with_extension("h");
        generate_bindings(&bindgen_flags[..], out_dir, &data_header)
            .expect("Failed generating data bindings!");
    }

    Ok(())
}
