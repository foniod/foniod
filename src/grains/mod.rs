mod connection;
mod ebpf;
mod ebpf_io;
mod protocol;

pub mod dns;
pub mod file;
pub mod tcpv4;
pub mod tls;
pub mod udp;
pub mod syscalls;
pub mod statsd;

pub use crate::grains::ebpf::*;
pub use crate::grains::ebpf_io::*;

pub use crate::backends::Message;
pub use crate::metrics::kind::*;
pub use crate::metrics::{Measurement, Tags, ToTags, Unit};
pub use std::net::Ipv4Addr;

use redbpf::{Map, Module};

pub fn to_le(i: u16) -> u16 {
    (i >> 8) | (i << 8)
}

pub fn to_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

pub fn find_map_by_name<'a>(module: &'a Module, needle: &str) -> &'a Map {
    module.maps.iter().find(|v| v.name == needle).unwrap()
}
