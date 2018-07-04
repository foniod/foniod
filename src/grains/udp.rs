#![allow(non_camel_case_types)]

use grains::connection::get_volume_callback;
use grains::*;

pub struct UDP;

impl EBPFModule<'static> for UDP {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/udp.elf"))
    }

    fn handler(m: Map, upstream: &Backend) -> Result<PerfMap> {
        match m.name.as_str() {
            "udp_volume" => PerfMap::new(m, -1, 0, 128, || {
                get_volume_callback("udp", vec![upstream.clone()])
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
