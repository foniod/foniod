#![no_std]
#![no_main]
use redbpf_probes::xdp::prelude::*;
use ingraind_probes::dns::Event;

program!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(1024);

#[xdp("dns_queries")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;

    // DNS is at least 12 bytes
    let header = data.slice(12)?;
    if header[2] >> 3 & 0xF != 0u8 {
        return Ok(XdpAction::Pass);
    }

    // we got something that looks like DNS, send it to user space for parsing
    let event = Event {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };

    unsafe {
        events.insert(
            &ctx,
            &MapData::with_payload(event, data.offset() as u32, ctx.len() as u32),
        )
    };

    Ok(XdpAction::Pass)
}
