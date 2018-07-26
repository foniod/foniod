#![allow(non_camel_case_types)]

use grains::connection::{Connection, _data_connect, get_volume_callback};
use grains::*;

pub struct TCP4;

impl EBPFGrain<'static> for TCP4 {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"))
    }

    fn get_handler(id: &str) -> EventCallback {
        match id {
            "tcp4_connections" => Box::new(|raw| {
                let connection = Connection::from(_data_connect::from(raw));
                let mut tags = connection.to_tags();

                tags.insert("proto".to_string(), "tcp4".to_string());

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
