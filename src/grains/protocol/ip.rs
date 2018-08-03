use grains::protocol::ETH_HLEN;

pub use std::net::Ipv4Addr;

pub fn packet_len(buf: &[u8]) -> usize {
    ETH_HLEN + ((buf[ETH_HLEN + 2] as usize) << 8 | buf[ETH_HLEN + 3] as usize)
}

pub fn to_ipv4(bytes: u32) -> Ipv4Addr {
    let d = (bytes >> 24) as u8;
    let c = (bytes >> 16) as u8;
    let b = (bytes >> 8) as u8;
    let a = bytes as u8;

    Ipv4Addr::new(a, b, c, d)
}
