#[allow(non_camel_case_types)] 
mod outbound_tcpv4 {
    const OUTBOUND_TCPV4: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/outbound_tcpv4.elf"));
    include!(concat!(env!("OUT_DIR"), "/outbound_tcpv4.rs"));
}
