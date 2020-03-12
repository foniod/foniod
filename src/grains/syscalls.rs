use std::collections::HashMap;
use std::fs;
use std::os::raw::c_char;

use crate::grains::*;

use failure::Error;
use redbpf::uname::get_kernel_internal_version;
use redbpf::{HashMap as BPFHashMap, Module};

use ingraind_probes::syscalls::SyscallTracepoint;

type KSyms = HashMap<u64, String>;
#[derive(Serialize, Deserialize, Debug)]
pub struct SyscallConfig {
    symbol_map: Option<String>,
    monitor_syscalls: Vec<String>,
    ksyms: Option<KSyms>,
}
pub struct Syscall(pub SyscallConfig);

#[cfg(target_arch = "x86_64")]
const SYSCALL_PREFIX: &str = "__x64_sys_";

#[cfg(target_arch = "aarch64")]
const SYSCALL_PREFIX: &str = "__arm64_sys_";

impl EBPFProbe for Grain<Syscall> {
    fn attach(&mut self) -> MessageStreams {
        let prefix = if get_kernel_internal_version().unwrap() >= 0x041100 {
            SYSCALL_PREFIX
        } else {
            "sys_"
        };
        let bind_to = self.native.0.monitor_syscalls.clone();
        bind_to
            .iter()
            .flat_map(|syscall| self.attach_kprobes_to_names(&format!("{}{}", prefix, syscall)))
            .collect()
    }
}

impl EBPFGrain<'static> for Syscall {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(
            env!("OUT_DIR"),
            "/target/bpf/programs/syscalls/syscalls.elf"
        ))
    }

    fn loaded(&mut self, module: &mut Module) {
        let symfile = match self.0.symbol_map {
            Some(ref path) => path.clone(),
            None => "/proc/kallsyms".to_string(),
        };

        self.0.ksyms = Some(parse_symbol_map(&symfile).unwrap());

        let map = BPFHashMap::<u8, u64>::new(find_map_by_name(module, "host_pid")).unwrap();
        map.set(1u8, std::process::id() as u64);
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        let ksyms = self.0.ksyms.clone().unwrap();
        Box::new(move |raw| {
            let data = unsafe { std::ptr::read(raw.as_ptr() as *const SyscallTracepoint) };
            let mut tags = Tags::new();

            let syscall_name = ksyms[&data.syscall_nr].clone();
            tags.insert("syscall_str", syscall_name);

            tags.insert("process_id", data.id.to_string());
            tags.insert(
                "process_str",
                crate::grains::to_string(unsafe { &*(&data.comm as *const [c_char]) }),
            );

            Some(Message::Single(Measurement::new(
                COUNTER | HISTOGRAM,
                "syscall.enter".to_string(),
                Unit::Byte(1 as u64),
                tags,
            )))
        })
    }
}

fn parse_symbol_map(path: &str) -> Result<KSyms, Error> {
    let symmap = fs::read_to_string(path)?;
    Ok(symmap
        .lines()
        .map(|l| l.splitn(4, ' ').collect::<Vec<&str>>())
        .map(|tokens| {
            (
                u64::from_str_radix(&tokens[0], 16).unwrap(),
                tokens[2].to_string(),
            )
        })
        .collect())
}
