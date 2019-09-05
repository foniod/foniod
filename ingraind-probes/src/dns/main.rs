#![feature(const_fn, const_transmute, lang_items, start)]
#![no_std]
#![no_main]
use cty::*;

use redbpf_probes::bindings::*;
use redbpf_probes::maps::*;
use redbpf_probes::xdp::{xdp_md, XdpAction};
use redbpf_macros::{map, probe, xdp};

use ingraind_probes::dns::Event;

probe!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::new();

#[xdp("dns_queries")]
pub extern "C" fn probe(ctxp: *mut xdp_md) -> XdpAction {
    let ctx = unsafe { *ctxp };
    let (ip, transport) = match (ctx.ip(), ctx.transport()) {
        (Some(i), Some(t)) => (unsafe { *i }, t),
        _ => return XdpAction::Pass
    };
    let sport = transport.source();
    let dport = transport.dest();
    if sport != 53 && dport != 53 {
        return XdpAction::Pass;
    }
    let mut out: [u8; 100] = [0; 100];
    let data = match ctx.data() {
        Some(data) => data,
        None => return XdpAction::Pass
    };

    let event = Event {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest()
    };

    XdpAction::Pass
}