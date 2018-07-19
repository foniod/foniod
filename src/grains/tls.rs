#![allow(non_camel_case_types)]

use grains::*;

pub struct TLS;

impl EBPFModule<'static> for TLS {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tls.elf"))
    }

    fn socket_handler(sock: &Socket) -> Result<Option<Message>> {
        println!("data!");
        Ok(None)
    }
}
