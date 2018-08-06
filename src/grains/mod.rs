mod connection;
mod ebpf;
mod events;
mod perfhandler;
mod protocol;
mod sockethandler;

pub mod dns;
pub mod file;
pub mod tcpv4;
pub mod tls;
pub mod udp;

pub use grains::ebpf::*;
pub use grains::events::*;
pub use grains::perfhandler::PerfHandler;
pub use grains::sockethandler::SocketHandler;

pub use backends::{BackendHandler, Message};
pub use metrics::kind::*;
pub use metrics::{Measurement, Tags, Unit};
pub use std::net::Ipv4Addr;

pub fn to_le(i: u16) -> u16 {
    (i >> 8) | (i << 8)
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
