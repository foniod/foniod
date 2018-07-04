#![allow(non_camel_case_types)]

use grains::connection::{Connection, _data_connect, get_volume_callback};
use grains::*;

use metrics::kind::*;

pub struct TCP4;

impl EBPFModule<'static> for TCP4 {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"))
    }

    fn handler(m: Map, upstream: &Backend) -> Result<PerfMap> {
        match m.name.as_str() {
            "tcp4_connections" => PerfMap::new(m, -1, 0, 16, || {
                let upstream = upstream.clone();
                Box::new(move |raw| {
                    let name = "connection.out".to_string();

                    let connection = Connection::from(_data_connect::from(raw));
                    let mut tags = connection.to_tags();
                    tags.insert("proto".to_string(), "tcp4".to_string());

                    upstream.do_send(Measurement::new(
                        COUNTER | HISTOGRAM | METER,
                        name,
                        1,
                        None,
                        tags,
                    ));
                })
            }),
            "tcp4_volume" => PerfMap::new(m, -1, 0, 128, || {
                get_volume_callback("tcp4", vec![upstream.clone()])
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
