#![allow(non_camel_case_types)]

use grains::connection::get_volume_callback;
use grains::*;

pub struct DNS;

impl EBPFModule<'static> for DNS {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/dns.elf"))
    }

    fn handler(m: Map, upstreams: &[BackendHandler]) -> Result<PerfMap> {
        PerfMap::new(m, -1, 0, 128, move || {
            Box::new(move |raw| {
                println!("{:?}", raw);
            })
        })
    }
}
