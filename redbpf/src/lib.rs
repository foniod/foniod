extern crate bpf_sys;
extern crate goblin;
extern crate libc;
extern crate zero;

use bpf_sys::bpf_insn;
use goblin::elf::section_header as hdr;
use goblin::{elf::Elf, elf::SectionHeader, error};

use std::ffi::{CStr, CString, NulError};
use std::mem;
use std::os::unix::io::RawFd;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, LoadError>;

#[derive(Debug)]
pub enum LoadError {
    StringConversion,
    BPF,
    Section(String),
    Parse(goblin::error::Error),
    KernelRelease(String),
    Uname,
}

impl From<goblin::error::Error> for LoadError {
    fn from(e: goblin::error::Error) -> LoadError {
        LoadError::Parse(e)
    }
}

impl From<NulError> for LoadError {
    fn from(_e: NulError) -> LoadError {
        LoadError::StringConversion
    }
}

struct Module {
    bytes: Vec<u8>,
    programs: Vec<Program>,
    perfs: Vec<PerfMap>,
    license: String,
    kernel_version: u32,
}

struct Map {
    name: String,
    kind: u32,
    fd: u32,
}

struct PerfMap {
    fd: u32,
    name: String,
    page_count: u32,
    callback: Box<FnMut(&[u8])>,
}

enum ProgramKind {
    Kprobe,
    Kretprobe,
}

struct Program {
    kind: ProgramKind,
    name: String,
    code: Vec<bpf_insn>,
}

impl ProgramKind {
    fn to_prog_type(&self) -> bpf_sys::bpf_prog_type {
        use ProgramKind::*;
        match self {
            Kprobe | Kretprobe => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
        }
    }

    fn to_attach_type(&self) -> bpf_sys::bpf_probe_attach_type {
        use ProgramKind::*;
        match self {
            Kprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_ENTRY,
            Kretprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_RETURN,
        }
    }

    fn from_section(section: &str) -> Result<ProgramKind> {
        use ProgramKind::*;
        match section {
            "kretprobe" => Ok(Kretprobe),
            "kprobe" => Ok(Kprobe),
            sec => Err(LoadError::Section(sec.to_string())),
        }
    }
}

impl Program {
    fn new(name: &str, code: &[u8]) -> Result<Program> {
        let code = zero::read_array(code).to_vec();
        let mut names = name.splitn(2, '/');

        let kind = names.next().ok_or(parse_fail("section type"))?;
        let name = names.next().ok_or(parse_fail("section name"))?.to_string();
        let kind = ProgramKind::from_section(kind)?;

        Ok(Program { kind, name, code })
    }

    fn load(self, kernel_version: u32, license: String) -> Result<RawFd> {
        let clicense = CString::new(license)?;
        let cname = CString::new(self.name)?;
        let mut log_buffer = [0u8; 65535];

        let fd = unsafe {
            bpf_sys::bpf_prog_load(
                self.kind.to_prog_type(),
                cname.as_ptr() as *const i8,
                self.code.as_ptr(),
                self.code.len() as i32,
                clicense.as_ptr() as *const i8,
                kernel_version as u32,
                0 as i32,
                log_buffer.as_mut_ptr() as *mut i8,
                mem::size_of_val(&log_buffer) as u32,
            )
        };

        if fd < 0 {
            Err(LoadError::BPF)
        } else {
            Ok(fd)
        }
    }
}

impl Module {
    fn parse(bytes: Vec<u8>) -> Result<Module> {
        let object = Elf::parse(&bytes[..])?;
        let strings = object.shdr_strtab.to_vec()?;

        let mut maps: Vec<PerfMap> = vec![];
        let mut programs = vec![];
        let mut license = String::new();
        let mut kernel_version = 0u32;

        for shdr in object.section_headers.iter() {
            let name = strings[shdr.sh_name];
            let kind = shdr.sh_type;
            let content = data(&bytes, &shdr);

            match (kind, name) {
                (hdr::SHT_PROGBITS, "license") => license.insert_str(0, zero::read_str(content)),
                (hdr::SHT_PROGBITS, "version") => {
                    kernel_version = resolve_version(zero::read::<u32>(content).clone())
                }
                (hdr::SHT_PROGBITS, name) => programs.push(Program::new(&name, &content)?),
                _ => unreachable!(),
            }
        }

        Ok(Module {
            bytes: bytes.clone(),
            programs,
            perfs: vec![],
            license,
            kernel_version,
        })
    }
}

#[inline]
fn resolve_version(version: u32) -> u32 {
    match version {
        0xFFFFFFFE => get_kernel_version().unwrap(),
        _ => version,
    }
}

#[inline]
fn get_kernel_version() -> Result<u32> {
    let mut uname = libc::utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };

    let res = unsafe { libc::uname(&mut uname) };
    if res < 0 {
        return Err(LoadError::Uname);
    }

    let urelease = to_str(&uname.release);
    let err = || LoadError::KernelRelease(urelease.to_string());
    let err_ = |_| LoadError::KernelRelease(urelease.to_string());

    let mut release_package = urelease.splitn(2, '-');
    let mut release = release_package.next().ok_or(err())?.splitn(3, '.');

    let major = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;
    let minor = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;
    let patch = u32::from_str(release.next().ok_or(err())?).map_err(err_)?;

    Ok(major << 16 | minor << 8 | patch)
}

#[inline]
fn to_str(bytes: &[i8]) -> &str {
    unsafe {
        let cstr = CStr::from_ptr(bytes.as_ptr());
        std::str::from_utf8_unchecked(cstr.to_bytes())
    }
}

#[inline]
fn data<'d>(bytes: &'d [u8], shdr: &SectionHeader) -> &'d [u8] {
    let offset = shdr.sh_offset as usize;
    let end = (shdr.sh_offset + shdr.sh_size) as usize;

    &bytes[offset..end]
}

#[inline]
fn parse_fail(reason: &str) -> error::Error {
    error::Error::Malformed(format!("Failed to parse: {}", reason))
}
