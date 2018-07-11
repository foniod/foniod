use regex::Regex;
use std::env;
use std::ffi::OsString;
use std::process::Command;

pub const BUILD_FLAGS: [&'static str; 17] = [
    "-D__BPF_TRACING__",
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
];

pub const KERNEL_HEADERS: [&'static str; 6] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

#[derive(Debug)]
pub enum Error {
    OSUnsupported,
    KernelHeadersNotFound,
    InvalidOutput,
}

pub fn headers() -> Result<Vec<OsString>, Error> {
    let headers_base_path = env_kernel_path().or_else(|_| arch_kernel_path())?;

    Ok(KERNEL_HEADERS
        .iter()
        .map(|h| OsString::from(format!("-I{}{}", headers_base_path, h)))
        .collect())
}

pub fn env_kernel_path() -> Result<String, Error> {
    env::var("KERNEL_SOURCE").map_err(|_| Error::KernelHeadersNotFound)
}

pub fn arch_kernel_path() -> Result<String, Error> {
    let pacman = Command::new("pacman")
        .args(vec!["-Ql", "linux-headers"])
        .output()
        .map_err(|_| Error::OSUnsupported)?;

    if !pacman.status.success() {
        return Err(Error::KernelHeadersNotFound);
    }

    arch_filter_output(&String::from_utf8(pacman.stdout).unwrap())
}

fn arch_filter_output(output: &str) -> Result<String, Error> {
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"(?m)^linux-headers (/usr/lib/modules/(.*)/build/)$").unwrap();
    }

    let maybe = RE
        .captures_iter(&output)
        .next()
        .ok_or(Error::InvalidOutput)?;

    Ok(maybe[1].to_string())
}

mod test {
    #[test]
    fn test_arch_output() {
        use build::arch_filter_output;
        assert_eq!(
            arch_filter_output(
                r"
linux-headers /usr/
linux-headers /usr/lib/
linux-headers /usr/lib/modules/
linux-headers /usr/lib/modules/4.17.2-1-ARCH/
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/.config
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/.tmp_versions/
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/Kconfig
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/Makefile
linux-headers /usr/lib/modules/4.17.2-1-ARCH/build/Module.symvers
"
            ).unwrap(),
            "/usr/lib/modules/4.17.2-1-ARCH/build/"
        )
    }
}
