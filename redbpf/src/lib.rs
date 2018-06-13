extern crate bpf_sys;
extern crate goblin;
extern crate zero;

use bpf_sys::bpf_insn;
use goblin::elf::section_header as hdr;
use goblin::{elf::Elf, elf::SectionHeader, error};

struct Module {
    bytes: Vec<u8>,
    programs: Vec<Program>,
    perfs: Vec<PerfMap>,
    license: String,
    version: u32,
}

struct Probe {
    name: String,
    code: Vec<bpf_insn>,
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
        let probe = Probe {
            name,
            code,
        };

        match kind {
            "kretprobe" => Ok(Program::Kretprobe(probe)),
            "kprobe" => Ok(Program::Kprobe(probe)),
            _ => Err(error::Error::Malformed("Unknown program type".to_string())),
        }
    }
}

struct PerfMap {
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
        let mut version = 0u32;

        for shdr in object.section_headers.iter() {
            let name = strings[shdr.sh_name];
            let kind = shdr.sh_type;
            let content = data(&bytes, &shdr);

            match (kind, name) {
                (hdr::SHT_PROGBITS, "license") => license.insert_str(0, zero::read_str(content)),
                (hdr::SHT_PROGBITS, "version") => version = zero::read::<u32>(content).clone(),
                (hdr::SHT_PROGBITS, name) => programs.push(Program::new(&name, &content)?),
                _ => unreachable!(),
            }
        }

        Ok(Module {
            bytes: bytes.clone(),
            programs,
            perfs: vec![],
            license,
            version,
        })
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
