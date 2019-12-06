mod connection;
mod ebpf;
mod ebpf_io;
mod protocol;

pub mod dns;
pub mod file;
pub mod osquery;
pub mod statsd;
pub mod syscalls;
pub mod tcpv4;
pub mod tls;
pub mod udp;

pub use crate::grains::ebpf::*;
pub use crate::grains::ebpf_io::*;

pub use crate::backends::Message;
pub use crate::metrics::kind::*;
pub use crate::metrics::{Measurement, Tags, ToTags, Unit};
pub use std::net::Ipv4Addr;

use redbpf::{Map, Module};
use std::{os::raw::c_char, mem::transmute };

pub fn to_le(i: u16) -> u16 {
    (i >> 8) | (i << 8)
}

pub fn to_string(buf: &[c_char]) -> String {
    let x: &[u8] = unsafe { transmute(buf) };

    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

pub fn find_map_by_name<'a>(module: &'a Module, needle: &str) -> &'a Map {
    module.maps.iter().find(|v| v.name == needle).unwrap()
}
