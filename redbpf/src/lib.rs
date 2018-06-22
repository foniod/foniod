#![cfg_attr(feature = "cargo-clippy", allow(clippy))]

extern crate bpf_sys;
extern crate goblin;
extern crate libc;
extern crate zero;

pub mod cpus;
mod error;
mod perf;
pub mod uname;

use bpf_sys::{bpf_insn, bpf_map_def};
use error::{LoadError, Result};
use goblin::elf::{section_header as hdr, Elf, Reloc, SectionHeader, Sym};
use uname::get_kernel_internal_version;

use std::collections::HashMap;
use std::ffi::CString;
use std::mem;
use std::os::unix::io::RawFd;

pub use perf::*;
pub type VoidPtr = *mut std::os::raw::c_void;

pub struct Module {
    pub programs: Vec<Program>,
    pub maps: Vec<Map>,
    pub license: String,
    pub version: u32,
}

pub struct Program {
    pfd: Option<RawFd>,
    fd: Option<RawFd>,
    pub kind: ProgramKind,
    pub name: String,
    code: Vec<bpf_insn>,
    code_bytes: i32,
}

#[derive(Debug)]
pub enum ProgramKind {
    Kprobe,
    Kretprobe,
}

pub struct Map {
    pub name: String,
    pub kind: u32,
    fd: RawFd,
}

pub struct Rel {
    shndx: usize,
    target: usize,
    offset: u64,
    sym: usize,
}

impl ProgramKind {
    pub fn to_prog_type(&self) -> bpf_sys::bpf_prog_type {
        use ProgramKind::*;
        match self {
            Kprobe | Kretprobe => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE,
        }
    }

    pub fn to_attach_type(&self) -> bpf_sys::bpf_probe_attach_type {
        use ProgramKind::*;
        match self {
            Kprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_ENTRY,
            Kretprobe => bpf_sys::bpf_probe_attach_type_BPF_PROBE_RETURN,
        }
    }

    pub fn from_section(section: &str) -> Result<ProgramKind> {
        use ProgramKind::*;
        match section {
            "kretprobe" => Ok(Kretprobe),
            "kprobe" => Ok(Kprobe),
            sec => Err(LoadError::Section(sec.to_string())),
        }
    }
}

impl Program {
    pub fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code_bytes = code.len() as i32;
        let code = zero::read_array(code).to_vec();
        let name = name.to_string();
        let kind = ProgramKind::from_section(kind)?;

        Ok(Program {
            pfd: None,
            fd: None,
            kind,
            name,
            code,
            code_bytes,
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.fd.is_some()
    }

    pub fn is_attached(&self) -> bool {
        self.pfd.is_some()
    }

    pub fn load(&mut self, kernel_version: u32, license: String) -> Result<RawFd> {
        let clicense = CString::new(license)?;
        let cname = CString::new(self.name.clone())?;
        let mut log_buffer = [0u8; 65535];

        let fd = unsafe {
            bpf_sys::bpf_prog_load(
                self.kind.to_prog_type(),
                cname.as_ptr() as *const i8,
                self.code.as_ptr(),
                self.code_bytes,
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
            self.fd = Some(fd);
            Ok(fd)
        }
    }

    pub fn attach(&mut self) -> Result<RawFd> {
        let ev_name = CString::new(format!("{}{}", self.name, self.kind.to_attach_type())).unwrap();
        let cname = CString::new(self.name.clone()).unwrap();
        let pfd = unsafe {
            bpf_sys::bpf_attach_kprobe(
                self.fd.unwrap(),
                self.kind.to_attach_type(),
                ev_name.as_ptr(),
                cname.as_ptr(),
                0,
            )
        };

        if pfd < 0 {
            Err(LoadError::BPF)
        } else {
            self.pfd = Some(pfd);
            Ok(pfd)
        }
    }
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Module> {
        let object = Elf::parse(&bytes[..])?;
        let symtab = object.syms.to_vec();
        let shdr_relocs = &object.shdr_relocs;

        let mut rels = vec![];
        let mut programs = HashMap::new();
        let mut maps = HashMap::new();

        let mut license = String::new();
        let mut version = 0u32;

        for (shndx, shdr) in object.section_headers.iter().enumerate() {
            let (kind, name) = get_split_section_name(&object, &shdr, shndx)?;

            let section_type = shdr.sh_type;
            let content = data(&bytes, &shdr);

            match (section_type, kind, name) {
                (hdr::SHT_REL, _, _) => add_rel(&mut rels, shndx, &shdr, &shdr_relocs),
                (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
                (hdr::SHT_PROGBITS, Some("license"), _) => {
                    license = zero::read_str(content).to_string()
                }
                (hdr::SHT_PROGBITS, Some("maps"), Some(name)) => {
                    // Maps are immediately bpf_create_map'd
                    maps.insert(shndx, Map::load(name, &content)?);
                }
                (hdr::SHT_PROGBITS, Some(kind @ "kprobe"), Some(name))
                | (hdr::SHT_PROGBITS, Some(kind @ "kretprobe"), Some(name)) => {
                    programs.insert(shndx, Program::new(kind, name, &content)?);
                }
                _ => {}
            }
        }

        // Rewrite programs with relocation data
        for rel in rels.iter() {
            if programs.contains_key(&rel.target) {
                rel.apply(&mut programs, &maps, &symtab)?;
            }
        }

        let programs = programs.drain().map(|(_, v)| v).collect();
        let maps = maps.drain().map(|(_, v)| v).collect();
        Ok(Module {
            programs,
            maps,
            license,
            version,
        })
    }
}

#[inline]
fn get_split_section_name<'o>(
    object: &'o Elf,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name)
        .ok_or(LoadError::Section(format!(
            "Section name not found: {}",
            shndx
        )))?;

    let mut names = name.splitn(2, '/');

    let kind = names.next();
    let name = names.next();

    Ok((kind, name))
}

impl Rel {
    #[inline]
    pub fn apply(
        &self,
        programs: &mut HashMap<usize, Program>,
        maps: &HashMap<usize, Map>,
        symtab: &Vec<Sym>,
    ) -> Result<()> {
        let prog = programs.get_mut(&self.target).ok_or(LoadError::Reloc)?;
        let map = maps
            .get(&symtab[self.sym].st_shndx)
            .ok_or(LoadError::Reloc)?;
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;

        prog.code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        prog.code[insn_idx].imm = map.fd;

        Ok(())
    }
}

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: &bpf_map_def = zero::read(code);
        let cname = CString::new(name.clone())?;
        let fd = unsafe {
            bpf_sys::bpf_create_map(
                config.kind,
                cname.as_ptr(),
                config.key_size as i32,
                config.value_size as i32,
                config.max_entries as i32,
                config.map_flags as i32,
            )
        };
        if fd < 0 {
            return Err(LoadError::BPF);
        }

        Ok(Map {
            name: name.to_string(),
            kind: config.kind,
            fd,
        })
    }

    pub fn set(&mut self, key: VoidPtr, value: VoidPtr) {
        unsafe {
            bpf_sys::bpf_update_elem(self.fd, key, value, 0);
        }
    }

    pub fn get(&mut self, key: VoidPtr, value: VoidPtr) {
        unsafe {
            bpf_sys::bpf_lookup_elem(self.fd, key, value);
        }
    }

    pub fn delete(&mut self, key: VoidPtr) {
        unsafe {
            bpf_sys::bpf_delete_elem(self.fd, key);
        }
    }
}

#[inline]
fn add_rel(
    rels: &mut Vec<Rel>,
    shndx: usize,
    shdr: &SectionHeader,
    shdr_relocs: &Vec<(usize, Vec<Reloc>)>,
) {
    // if unwrap blows up, something's really bad
    let section_rels = &shdr_relocs.iter().find(|(idx, _)| idx == &shndx).unwrap().1;
    rels.extend(section_rels.iter().map(|rel| Rel {
        shndx,
        target: shdr.sh_info as usize,
        sym: rel.r_sym,
        offset: rel.r_offset,
    }));
}

#[inline]
fn get_version(bytes: &[u8]) -> u32 {
    let version = zero::read::<u32>(bytes);
    match version {
        0xFFFFFFFE => get_kernel_internal_version().unwrap(),
        _ => version.clone(),
    }
}

#[inline]
fn data<'d>(bytes: &'d [u8], shdr: &SectionHeader) -> &'d [u8] {
    let offset = shdr.sh_offset as usize;
    let end = (shdr.sh_offset + shdr.sh_size) as usize;

    &bytes[offset..end]
}
