extern crate bpf_sys;
extern crate goblin;
extern crate zero;

use bpf_sys::bpf_insn;
use goblin::elf::section_header as hdr;
use goblin::{elf::Elf, elf::SectionHeader, error};

use std::ffi::{CString, NulError};
use std::mem;
use std::os::unix::io::RawFd;

struct Module {
    bytes: Vec<u8>,
    programs: Vec<Program>,
    perfs: Vec<PerfMap>,
    license: String,
    kernel_version: u32,
}

struct Probe {
    name: String,
    code: Vec<bpf_insn>,
}

#[derive(Debug)]
enum LoadError {
    ConversionError,
    BPFError,
}

impl From<NulError> for LoadError {
    fn from(e: NulError) -> LoadError {
        LoadError::ConversionError
    }
}

impl Probe {
    fn load(self, kernel_version: u32, license: String) -> Result<RawFd, LoadError> {
        let clicense = CString::new(license)?;
        let cname = CString::new(self.name)?;
        let mut log_buffer = [0u8; 65535];

        let inserted = unsafe {
            bpf_sys::bpf_prog_load(
                bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
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

        if inserted < 0 {
            Err(LoadError::BPFError)
        } else {
            Ok(inserted)
        }
    }
}

enum Program {
    Kprobe(Probe),
    Kretprobe(Probe),
}

impl Program {
    fn new(name: &str, code: &[u8]) -> error::Result<Program> {
        let code = zero::read_array(code).to_vec();
        let mut names = name.splitn(2, '/');

        let kind = names.next().ok_or(parse_fail("section type"))?;
        let name = names.next().ok_or(parse_fail("section name"))?.to_string();
        let probe = Probe { name, code };

        match kind {
            "kretprobe" => Ok(Program::Kretprobe(probe)),
            "kprobe" => Ok(Program::Kprobe(probe)),
            _ => Err(error::Error::Malformed("Unknown program type".to_string())),
        }
    }

    fn load(self, kernel_version: u32, license: String) -> Result<RawFd, LoadError> {
        use Program::*;
        match self {
            Kprobe(p) | Kretprobe(p) => p.load(kernel_version, license),
        }
    }
}

struct Map {
    name: String,
    kind: u32,
    fd: u32,
}

struct PerfMap {
    fd: u32,
    name: String,
    pageCount: u32,
    callback: Box<FnMut(&[u8])>,
}

impl Module {
    fn parse(bytes: Vec<u8>) -> error::Result<Module> {
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
        0xFFFFFFFE => get_kernel_version(),
        _ => version,
    }
}

#[inline]
fn get_kernel_version() -> u32 {
    // TODO
    1u32
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
