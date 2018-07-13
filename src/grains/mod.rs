mod connection;
pub mod dns;
pub mod tcpv4;
pub mod udp;

pub use backends::{BackendHandler, Message};
pub use metrics::Measurement;
pub use redbpf::{LoadError, PerfMap, Result};
pub use std::collections::HashMap;
pub use std::net::Ipv4Addr;
use std::marker::PhantomData;

use redbpf::{Map, Module};

pub struct Grain<T> {
    module: Module,
    _type: PhantomData<T>,
}

pub struct ActiveGrain<T> {
    grain: Grain<T>,
    perfmaps: Vec<PerfMap>,
}

impl<'code, 'module, T> Grain<T>
where
    T: EBPFModule<'code>,
{
    pub fn load() -> Result<Self> {
        let mut module = Module::parse(T::code())?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
        }

        Ok(Grain {
            module,
            _type: PhantomData,
        })
    }

    pub fn attach_kprobes(mut self) -> Self {
        use redbpf::ProgramKind::*;
        for prog in self
            .module
            .programs
            .iter_mut()
            .filter(|p| p.kind == Kprobe || p.kind == Kretprobe)
        {
            println!("Program: {}, {:?}", prog.name, prog.kind);
            prog.attach_probe().unwrap();
        }

        self
    }

    pub fn attach_xdps(mut self, iface: &str) -> Self {
        use redbpf::ProgramKind::*;
        for prog in self.module.programs.iter_mut().filter(|p| p.kind == XDP) {
            println!("Program: {}, {:?}", prog.name, prog.kind);

            prog.attach_xdp(iface).unwrap();
        }

        self
    }

    pub fn attach_socketfilters(mut self, iface: &str) -> Self {
        use redbpf::ProgramKind::*;
        for prog in self.module.programs.iter_mut().filter(|p| p.kind == SocketFilter) {
            println!("Program: {}, {:?}", prog.name, prog.kind);

            prog.attach_socketfilter(iface).unwrap();
        }

        self
    }


    pub fn bind(mut self, backends: Vec<BackendHandler>) -> ActiveGrain<T> {
        let perfmaps = self
            .module
            .maps
            .drain(..)
            .map(|m| T::handler(m, &backends[..]))
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .collect();

        ActiveGrain {
            grain: self,
            perfmaps,
        }
    }
}

impl<T> ActiveGrain<T> {
    pub fn poll(&mut self) {
        for pm in self.perfmaps.iter_mut() {
            pm.poll(10);
        }
    }
}

pub trait EBPFModule<'code> {
    fn code() -> &'code [u8];
    fn handler(map: Map, upstream: &[BackendHandler]) -> Result<PerfMap>;
}

pub fn to_le(i: u16) -> u16 {
    (i >> 8) | (i << 8)
}

pub fn to_ip(bytes: u32) -> Ipv4Addr {
    let d = (bytes >> 24) as u8;
    let c = (bytes >> 16) as u8;
    let b = (bytes >> 8) as u8;
    let a = bytes as u8;

    Ipv4Addr::new(a, b, c, d)
}

pub fn to_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}
