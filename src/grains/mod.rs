mod connection;
pub mod dns;
pub mod tcpv4;
pub mod tls;
pub mod udp;

pub use backends::{BackendHandler, Message};
pub use metrics::kind::*;
pub use metrics::{Measurement, Unit};
pub use redbpf::{LoadError, PerfMap, Result};
pub use std::collections::HashMap;
use std::marker::PhantomData;
pub use std::net::Ipv4Addr;

use redbpf::{Map, Module};

use lazy_socket::raw as lazy_socket;
use lazy_socket::raw::Socket;
use std::os::unix::io::FromRawFd;

pub struct Grain<T> {
    module: Module,
    _type: PhantomData<T>,
}

pub struct PerfGrain<T> {
    grain: Grain<T>,
    perfmaps: Vec<PerfMap>,
}

pub struct SocketGrain<T> {
    grain: Grain<T>,
    sockets: Vec<Socket>,
    backends: Vec<BackendHandler>,
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

    pub fn attach_kprobes(mut self, backends: &[BackendHandler]) -> impl Pollable {
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

        self.bind(backends)
    }

    pub fn attach_xdps(mut self, iface: &str, backends: &[BackendHandler]) -> impl Pollable {
        use redbpf::ProgramKind::*;
        for prog in self.module.programs.iter_mut().filter(|p| p.kind == XDP) {
            println!("Program: {}, {:?}", prog.name, prog.kind);

            prog.attach_xdp(iface).unwrap();
        }

        self.bind(backends)
    }

    fn bind(mut self, backends: &[BackendHandler]) -> PerfGrain<T> {
        let perfmaps = self
            .module
            .maps
            .drain(..)
            .filter(|m| m.kind == 4)
            .map(|m| T::get_perf_map(m, backends))
            .map(Result::unwrap)
            .collect();

        PerfGrain {
            grain: self,
            perfmaps,
        }
    }

    pub fn attach_socketfilters(
        mut self,
        iface: &str,
        backends: &[BackendHandler],
    ) -> impl Pollable {
        use redbpf::ProgramKind::*;
        let sockets = self
            .module
            .programs
            .iter_mut()
            .filter(|p| p.kind == SocketFilter)
            .map(|prog| {
                println!("Program: {}, {:?}", prog.name, prog.kind);
                let fd = prog.attach_socketfilter(iface).unwrap();
                unsafe { Socket::from_raw_fd(fd) }
            })
            .collect::<Vec<Socket>>();

        SocketGrain {
            grain: self,
            sockets,
            backends: backends.to_vec(),
        }
    }
}

pub trait Pollable {
    fn poll(&mut self);
}

impl<T> Pollable for PerfGrain<T> {
    fn poll(&mut self) {
        for pm in self.perfmaps.iter_mut() {
            pm.poll(10);
        }
    }
}

impl<'code, 'module, T> Pollable for SocketGrain<T>
where
    T: EBPFModule<'code>,
{
    fn poll(&mut self) {
        let sockets: Vec<&Socket> = self.sockets.iter().map(|s| s).collect();
        if lazy_socket::select(&sockets.as_slice(), &[], &[], Some(10)).unwrap() < 1 {
            return;
        }

        for sock in self.sockets.iter() {
            T::socket_handler(sock)
                .unwrap()
                .and_then(|msg| Some(send_to(&self.backends, msg)));
        }
    }
}

pub trait EBPFModule<'code> {
    fn code() -> &'code [u8];
    fn get_perf_map(_map: Map, _upstream: &[BackendHandler]) -> Result<PerfMap> {
        Err(LoadError::BPF)
    }

    fn socket_handler(_sock: &Socket) -> Result<Option<Message>> {
        Err(LoadError::BPF)
    }
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

pub fn send_to(upstreams: &[BackendHandler], msg: Message) {
    for upstream in upstreams.iter() {
        upstream.do_send(msg.clone()).unwrap();
    }
}
