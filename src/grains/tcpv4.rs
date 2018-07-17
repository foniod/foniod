#![allow(non_camel_case_types)]

use grains::connection::{Connection, _data_connect, get_volume_callback};
use grains::*;

pub struct TCP4;

impl EBPFModule<'static> for TCP4 {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"))
    }

    fn handler(m: Map, upstreams: &[BackendHandler]) -> Result<PerfMap> {
        match m.name.as_str() {
            "tcp4_connections" => PerfMap::new(m, -1, 0, 16, || {
                let upstreams = upstreams.to_vec();
                Box::new(move |raw| {
                    let connection = Connection::from(_data_connect::from(raw));
                    let mut tags = connection.to_tags();

                    tags.insert("proto".to_string(), "tcp4".to_string());

                    send_to(
                        &upstreams,
                        Message::Single(Measurement::new(
                            COUNTER | HISTOGRAM | METER,
                            "connection.out".to_string(),
                            Unit::Count(1),
                            tags.clone(),
                        )),
                    );
                })
            }),
            "tcp4_volume" => PerfMap::new(m, -1, 0, 128, || {
                get_volume_callback("tcp4", upstreams.to_vec())
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
