#![allow(non_camel_case_types)]

use grains::connection::get_volume_callback;
use grains::*;

pub struct UDP;
impl ToEpollHandler for Grain<UDP> {
    fn to_eventoutputs(&mut self, backends: &[BackendHandler]) -> EventOutputs {
        self.attach_kprobes(backends)
    }
}

impl EBPFGrain<'static> for UDP {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/udp.elf"))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        get_volume_callback("udp")
    }
}
