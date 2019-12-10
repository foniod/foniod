use cty::*;

use core::fmt::Debug;
use redbpf_probes::bindings::*;

#[repr(C)]
pub struct Ipv6Addr(in6_addr);

impl From<in6_addr> for Ipv6Addr {
    #[inline]
    fn from(src: in6_addr) -> Ipv6Addr {
        Ipv6Addr(src)
    }
}

impl Debug for Ipv6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            write!(
                f,
                "::{:x}::{:x}::{:x}::{:x}::{:x}::{:x}::{:x}::{:x}",
                self.0.in6_u.u6_addr16[0],
                self.0.in6_u.u6_addr16[1],
                self.0.in6_u.u6_addr16[2],
                self.0.in6_u.u6_addr16[3],
                self.0.in6_u.u6_addr16[4],
                self.0.in6_u.u6_addr16[5],
                self.0.in6_u.u6_addr16[6],
                self.0.in6_u.u6_addr16[7]
            )
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    pub ts: u64,
    pub pid: u32,
    pub typ: u32,
    pub sport: u32,
    pub dport: u32,
    pub comm: [c_char; 16],
    pub saddr: Ipv6Addr,
    pub daddr: Ipv6Addr,
}

#[derive(Debug)]
pub enum Message {
    Send(Connection, u16),
    Receive(Connection, u16),
}
