mod ebpf;
mod ebpf_io;
mod protocol;

pub mod dns;
pub mod file;
pub mod osquery;
pub mod statsd;
pub mod syscalls;
pub mod tls;
pub mod network;
pub mod test;

use actix::Recipient;

pub use crate::grains::ebpf::*;
pub use crate::grains::ebpf_io::*;

pub use crate::backends::Message;
pub use crate::metrics::kind::*;
pub use crate::metrics::{Measurement, Tags, ToTags, Unit};
pub use std::net::Ipv4Addr;

use redbpf::{Map, Module};
use std::{os::raw::c_char, mem::transmute };
trait SendToManyRecipients {
    fn do_send(&self, message: Message) {
        let recipients = self.recipients();
        for (i, r) in recipients.iter().enumerate() {
            if i == recipients.len() - 1 {
                r.do_send(message).unwrap();
                break;
            }
            r.do_send(message.clone()).unwrap();
        }
    }

    fn recipients(&self) -> &Vec<Recipient<Message>>;
}

impl SendToManyRecipients for Vec<Recipient<Message>> {
    fn recipients(&self) -> &Vec<Recipient<Message>> {
        self
    }
}


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
