#![allow(non_camel_case_types)]

use crate::grains::connection::get_volume_callback;
use crate::grains::*;

pub struct UDP;

impl EBPFProbe for Grain<UDP> {
    fn attach(&mut self) -> MessageStreams {
        self.attach_kprobes()
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
