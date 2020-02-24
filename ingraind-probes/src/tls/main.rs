#![no_std]
#![no_main]
use core::mem;
use memoffset::offset_of;

use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[socket_filter("tls_handshake")]
pub fn tls_handshake(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto: u16 = skb.load(offset_of!(ethhdr, h_proto))?;
    let ip_proto: u8 = skb.load(eth_len + offset_of!(iphdr, protocol))?;

    // only parse TCP
    if !(eth_proto as u32 == ETH_P_IP && ip_proto as u32 == IPPROTO_TCP) {
        return Ok(SkBuffAction::Ignore);
    }

    // compute the start of the TLS payload
    let ip_hdr_len = ((skb.load::<u8>(eth_len)? & 0x0F) << 2) as usize;
    let tcp_len = ((skb.load::<u8>(eth_len + ip_hdr_len as usize + 12)? >> 4) << 2) as usize;
    let tls = eth_len + ip_hdr_len + tcp_len;

    // parse the TLS version
    let content_type: u8 = skb.load(tls)?;
    let major: u8 = skb.load(tls + 1)?;
    let minor: u8 = skb.load(tls + 2)?;
    if content_type == 0x16u8 && major <= 0x03u8 && minor <= 0x04u8 {
        return Ok(SkBuffAction::SendToUserspace);
    }

    return Ok(SkBuffAction::Ignore);
}
