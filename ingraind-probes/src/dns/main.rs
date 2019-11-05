#![no_std]
#![no_main]
use cty::*;
use core::slice;
use core::mem;

use redbpf_probes::bindings::*;
use redbpf_probes::maps::*;
use redbpf_probes::xdp::{xdp_md, XdpAction, XdpContext};
use redbpf_macros::{map, probe, xdp};

use ingraind_probes::dns::Event;

probe!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::new();

#[xdp("dns_queries")]
pub extern "C" fn probe(ctx: XdpContext) -> XdpAction {
    let (ip, transport) = match (ctx.ip(), ctx.transport()) {
        (Some(i), Some(t)) => (unsafe { *i }, t),
        _ => return XdpAction::Pass
    };
    let data = match ctx.data() {
        Some(data) => data,
        None => return XdpAction::Pass
    };

    let header = match data.slice(12) {
        Some(s) => s,
        None => return XdpAction::Pass
    };

    if header[2] >> 3 & 0xF != 0u8 {
        return XdpAction::Pass
    }

    let offset = data.offset() as u32;
    let size = data.len() as u32;

    let event = Event {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
        offset,
        size,
        data: []
    };

    unsafe { events.insert(ctx.inner(), event) }

    XdpAction::Pass
}
