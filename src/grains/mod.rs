mod connection;
pub mod dns;
pub mod tcpv4;
pub mod tls;
pub mod udp;

pub use backends::{BackendHandler, Message};
pub use metrics::kind::*;
pub use metrics::{Measurement, Tags, Unit};
pub use std::net::Ipv4Addr;

use redbpf::cpus;
use redbpf::{Module, PerfMap, Result};

use epoll;
use lazy_socket::raw::Socket;
use std::io;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::slice;

pub struct Grain<T> {
    module: Module,
    _type: PhantomData<T>,
}

pub struct PerfHandler {
    name: String,
    perfmap: PerfMap,
    callback: EventCallback,
    backends: Vec<BackendHandler>,
}

pub struct SocketHandler {
    socket: Socket,
    callback: EventCallback,
    backends: Vec<BackendHandler>,
}

impl<'code, 'module, T> Grain<T>
where
    T: EBPFGrain<'code>,
{
    pub fn attach_kprobes(&mut self, backends: &[BackendHandler]) -> Vec<Box<dyn EventHandler>> {
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

        self.bind_perf(backends)
    }

    pub fn attach_xdps(
        &mut self,
        iface: &str,
        backends: &[BackendHandler],
    ) -> Vec<Box<dyn EventHandler>> {
        use redbpf::ProgramKind::*;
        for prog in self.module.programs.iter_mut().filter(|p| p.kind == XDP) {
            println!("Program: {}, {:?}", prog.name, prog.kind);
            prog.attach_xdp(iface).unwrap();
        }

        self.bind_perf(backends)
    }

    fn bind_perf(&mut self, backends: &[BackendHandler]) -> Vec<Box<dyn EventHandler>> {
        let online_cpus = cpus::get_online().unwrap();
        let mut output: Vec<Box<dyn EventHandler>> = vec![];
        for ref mut m in self.module.maps.iter_mut().filter(|m| m.kind == 4) {
            for cpuid in online_cpus.iter() {
                let pm = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
                output.push(Box::new(PerfHandler {
                    name: m.name.clone(),
                    perfmap: pm,
                    callback: T::get_handler(m.name.as_str()),
                    backends: backends.to_vec(),
                }));
            }
        }

        output
    }

    pub fn attach_socketfilters(
        mut self,
        iface: &str,
        backends: &[BackendHandler],
    ) -> Vec<Box<dyn EventHandler>> {
        use redbpf::ProgramKind::*;
        self.module
            .programs
            .iter_mut()
            .filter(|p| p.kind == SocketFilter)
            .map(|prog| {
                println!("Program: {}, {:?}", prog.name, prog.kind);
                let fd = prog.attach_socketfilter(iface).unwrap();
                Box::new(SocketHandler {
                    socket: unsafe { Socket::from_raw_fd(fd) },
                    backends: backends.to_vec(),
                    callback: T::get_handler(prog.name.as_str()),
                }) as Box<dyn EventHandler>
            })
            .collect()
    }
}

pub trait EventHandler {
    fn fd(&self) -> RawFd;
    fn poll(&self);
}

impl EventHandler for PerfHandler {
    fn fd(&self) -> RawFd {
        self.perfmap.fd
    }
    fn poll(&self) {
        use redbpf::Event;

        while let Some(ev) = self.perfmap.read() {
            match ev {
                Event::Lost(lost) => {
                    println!("Possibly lost {} samples for {}", lost.count, &self.name);
                }
                Event::Sample(sample) => {
                    let msg = unsafe {
                        (self.callback)(slice::from_raw_parts(
                            sample.data.as_ptr(),
                            sample.size as usize,
                        ))
                    };
                    msg.and_then(|m| Some(send_to(&self.backends, m)));
                }
            }
        }
    }
}

const ETH_HLEN: usize = 14;
fn packet_len(buf: &[u8]) -> usize {
    ETH_HLEN + ((buf[ETH_HLEN + 2] as usize) << 8 | buf[ETH_HLEN + 3] as usize)
}

impl EventHandler for SocketHandler {
    fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
    fn poll(&self) {
        let mut buf = [0u8; 32*1024];
        let mut headbuf = [0u8; ETH_HLEN + 4];

        while self.socket.recv(&mut headbuf, 0x02 /* MSG_PEEK */).is_ok() {
            let plen = packet_len(&headbuf);
            let read = self.socket.recv(&mut buf[..plen], 0).unwrap();
            if read <= ETH_HLEN {
                return;
            }

            let msg = match read {
                0 => None,
                _ => (self.callback)(&buf[..plen]),
            };

            msg.and_then(|msg| Some(send_to(&self.backends, msg)));
        }
    }
}

pub type EventCallback = Box<Fn(&[u8]) -> Option<Message> + Send>;
pub trait EBPFGrain<'code> {
    fn code() -> &'code [u8];
    fn get_handler(id: &str) -> EventCallback;

    fn load() -> Result<Grain<Self>>
    where
        Self: Sized,
    {
        let mut module = Module::parse(Self::code())?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
        }

        Ok(Grain {
            module,
            _type: PhantomData,
        })
    }
}

pub fn epoll_loop(events: Vec<Box<dyn EventHandler>>, timeout: i32) -> io::Result<()> {
    let efd = epoll::create(true)?;

    for eh in events.iter() {
        let fd = eh.fd();
        let hptr = eh as *const Box<dyn EventHandler> as u64;

        epoll::ctl(
            efd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(epoll::Events::EPOLLIN, hptr),
        )?;
    }

    let mut eventsbuf: Vec<epoll::Event> = events
        .iter()
        .map(|_| epoll::Event::new(epoll::Events::empty(), 0))
        .collect();

    loop {
        match epoll::wait(efd, timeout, eventsbuf.as_mut_slice()) {
            Err(err) => return Err(err),
            Ok(0) => continue,
            Ok(x) => for ev in eventsbuf[..x].iter() {
                let handler =
                    unsafe { (ev.data as *const Box<dyn EventHandler>).as_ref().unwrap() };
                handler.poll();
            },
        }
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
