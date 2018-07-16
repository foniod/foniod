#![allow(non_camel_case_types)]

use grains::connection::get_volume_callback;
use grains::*;

pub struct UDP;

impl EBPFModule<'static> for UDP {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/udp.elf"))
    }

    fn handler(m: Map, upstreams: &[BackendHandler]) -> Result<PerfMap> {
        PerfMap::new(m, -1, 0, 128, move || {
            get_volume_callback("udp", upstreams.to_vec())
        })
    }
}
