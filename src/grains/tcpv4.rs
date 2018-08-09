#![allow(non_camel_case_types)]

use grains::connection::{Connection, _data_connect, get_volume_callback};
use grains::*;

pub struct TCP4;

impl EBPFGrain<'static> for TCP4 {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"))
    }

    fn get_handler(&self, id: &str) -> EventCallback {
        match id {
            "tcp4_connections" => Box::new(|raw| {
                let mut connection = Connection::from(_data_connect::from(raw));
                connection.proto = "tcp4".to_string();
                let tags = connection.to_tags();

                Some(Message::Single(Measurement::new(
                    COUNTER | HISTOGRAM | METER,
                    "connection.out".to_string(),
                    Unit::Count(1),
                    tags,
                )))
            }),
            "tcp4_volume" => get_volume_callback("tcp4"),
            _ => unreachable!(),
        }
    }
}
