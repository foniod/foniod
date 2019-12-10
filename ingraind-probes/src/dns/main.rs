#![no_std]
#![no_main]
use core::mem;
use core::slice;
use cty::*;

use redbpf_macros::{map, program, xdp};
use redbpf_probes::bindings::*;
use redbpf_probes::maps::*;
use redbpf_probes::xdp::{MapData, PerfMap, XdpAction, XdpContext};

use ingraind_probes::dns::Event;

program!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(1024);

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

    let event = Event {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };

    unsafe {
        events.insert(
            &ctx,
            MapData::with_payload(event, data.offset() as u32, data.len() as u32),
        )
    };

    XdpAction::Pass
}
