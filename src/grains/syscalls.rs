use std::collections::HashMap;
use std::fs;

use crate::grains::*;

use failure::Error;
use redbpf::{Module, VoidPtr};

include!(concat!(env!("OUT_DIR"), "/syscall.rs"));

type KSyms = HashMap<u64, String>;
#[derive(Serialize, Deserialize, Debug)]
pub struct SyscallConfig {
    symbol_map: Option<String>,
    monitor_syscalls: Vec<String>,
    ksyms: Option<KSyms>,
}
pub struct Syscall(pub SyscallConfig);

impl ToEpollHandler for Grain<Syscall> {
    fn to_eventoutputs(&mut self, backends: &[BackendHandler]) -> EventOutputs {
        let bind_to = self.native.0.monitor_syscalls.clone();
        bind_to
            .iter()
            .flat_map(|syscall| {
                self.attach_kprobes_to_names(&format!("__x64_sys_{}", syscall), backends)
            })
            .collect()
    }
}

impl EBPFGrain<'static> for Syscall {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/syscall.elf"))
    }

    fn loaded(&mut self, module: &mut Module) {
        let symfile = match self.0.symbol_map {
            Some(ref path) => path.clone(),
            None => "/proc/kallsyms".to_string(),
        };

        self.0.ksyms = Some(parse_symbol_map(&symfile).unwrap());

        let map = find_map_by_name(module, "host_pid");
        let mut pid = std::process::id();
        map.set(&mut 1u8 as *mut u8 as VoidPtr,
                &mut pid as *mut u32 as VoidPtr);
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        let ksyms = self.0.ksyms.clone().unwrap();
        Box::new(move |raw| {
            let data = _data_syscall_tracepoint::from(raw);
            let mut tags = Tags::new();

            let syscall_name = ksyms[&data.syscall_nr].clone();
            tags.insert("syscall", syscall_name);

            tags.insert("task_id", data.id.to_string());
            tags.insert("process", crate::grains::to_string(
                unsafe { &*(&data.comm as *const [i8] as *const [u8]) }
            ));

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
        .map(|tokens| (u64::from_str_radix(&tokens[0], 16).unwrap(), tokens[2].to_string()))
        .collect())
}
