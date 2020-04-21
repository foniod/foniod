use crate::backends::Message;
use crate::grains::ebpf_io::{
    MessageStream, MessageStreams, PerfMessageStream, SocketMessageStream,
};
use crate::grains::SendToManyRecipients;

use redbpf::{cpus, xdp, Module, PerfMap, Result};

use actix::{Actor, AsyncContext, Context, Recipient, StreamHandler};
use lazy_socket::raw::Socket;
use std::convert::Into;
use std::os::unix::io::FromRawFd;

pub struct Grain<T> {
    module: Module,
    pub native: T,
}

pub type EventCallback = Box<dyn Fn(&[u8]) -> Option<Message> + Send>;

pub trait EBPFGrain<'code>: Sized {
    fn code() -> &'code [u8];
    fn get_handler(&self, id: &str) -> EventCallback;
    fn loaded(&mut self, _module: &mut Module) {}

    fn load(mut self) -> Result<Grain<Self>>
    where
        Self: Sized,
    {
        let mut module = Module::parse(Self::code())?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
        }

        self.loaded(&mut module);
        Ok(Grain {
            module,
            native: self,
        })
    }
}

impl<'code, 'module, T> Grain<T>
where
    T: EBPFGrain<'code>,
{
    pub fn attach_kprobes(&mut self) -> MessageStreams {
        for prog in self.module.kprobes_mut() {
            info!("Loaded: {}, {}", prog.name(), prog.attach_type_str());
            prog.attach_kprobe(&prog.name(), 0).unwrap();
        }

        self.bind_perf()
    }

    pub fn attach_kprobes_to_name(&mut self, name: &str) -> MessageStreams {
        for prog in self.module.kprobes_mut() {
            info!("Loaded: {}, {}", name, prog.attach_type_str());
            prog.attach_kprobe(name, 0).unwrap();
        }

        self.bind_perf()
    }

    pub fn attach_xdps(&mut self, iface: &str, flags: xdp::Flags) -> MessageStreams {
        for prog in self.module.xdps_mut() {
            info!("Loaded: {}, XDP", prog.name());
            prog.attach_xdp(iface, flags).unwrap();
        }

        self.bind_perf()
    }

    pub fn attach_tracepoints(&mut self, category: &str, name: &str) -> MessageStreams {
        for prog in self.module.trace_points_mut() {
            info!("Attached: {}, Tracepoint", name);
            prog.attach_trace_point(category, name).unwrap();
        }

        self.bind_perf()
    }

    fn bind_perf(&mut self) -> MessageStreams {
        let online_cpus = cpus::get_online().unwrap();
        let mut streams: MessageStreams = vec![];
        for m in self.module.maps.iter_mut().filter(|m| m.kind == 4) {
            for cpuid in online_cpus.iter() {
                let map = PerfMap::bind(m, -1, *cpuid, 16, -1, 0).unwrap();
                let stream = Box::new(PerfMessageStream::new(
                    m.name.clone(),
                    map,
                    self.native.get_handler(m.name.as_str()),
                ));
                streams.push(stream);
            }
        }

        streams
    }

    pub fn attach_socketfilters(&mut self, iface: &str) -> MessageStreams {
        let socket_fds = self
            .module
            .socket_filters_mut()
            .map(|prog| {
                info!("Attached: {}, SocketFilter", prog.name());
                prog.attach_socket_filter(iface).unwrap()
            })
            .collect::<Vec<_>>();

        // we need to get out of mutable borrow land to continue.
        // this is because we cannot simultaneously borrow the `native` as
        // immutable and `programs ` as mutable
        self.module
            .socket_filters()
            .zip(&socket_fds)
            .map(|(prog, fd)| {
                Box::new(SocketMessageStream::new(
                    &prog.name(),
                    unsafe { Socket::from_raw_fd(*fd) },
                    self.native.get_handler(&prog.name()),
                )) as Box<MessageStream>
            })
            .collect()
    }
}

pub trait EBPFProbe: Send {
    fn attach(&mut self) -> MessageStreams;
}

pub struct EBPFActor {
    probe: Box<dyn EBPFProbe>,
    recipients: Vec<Recipient<Message>>,
}

impl EBPFActor {
    pub fn new(probe: Box<dyn EBPFProbe>, recipients: Vec<Recipient<Message>>) -> Self {
        EBPFActor { probe, recipients }
    }
}

impl Actor for EBPFActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let mut streams = self.probe.attach();
        for stream in streams.drain(..) {
            ctx.add_stream(stream);
        }
    }
}

impl StreamHandler<Vec<Message>> for EBPFActor {
    fn handle(&mut self, mut messages: Vec<Message>, _ctx: &mut Context<Self>) {
        for message in messages.drain(..) {
            self.recipients.do_send(message);
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum XdpMode {
    Auto,
    Skb,
    Driver,
    Hardware,
}

impl Into<xdp::Flags> for XdpMode {
    fn into(self) -> xdp::Flags {
        use xdp::Flags::*;
        use XdpMode::*;
        match self {
            Auto => xdp::Flags::default(),
            Skb => SkbMode,
            Driver => DrvMode,
            Hardware => HwMode,
        }
    }
}

pub fn default_xdp_mode() -> XdpMode {
    XdpMode::Auto
}
