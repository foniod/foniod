#![allow(non_camel_case_types)]

use grains::connection::{Connection, Volume, _data_connect, _data_volume};
use grains::*;
use redbpf::{LoadError, PerfMap, Result};
use serde::{Deserialize, Serialize};

use cadence::StatsdClient;

pub struct TCP4;

const MODULE_TCPV4: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"));

impl<'m> EBPFModule<'static, 'm> for TCP4 {
    fn code() -> &'static [u8] {
        MODULE_TCPV4
    }

    fn handler(m: &'m mut Map, statsd: &StatsdClient) -> Result<PerfMap<'m>> {
        match m.name.as_str() {
            "tcp4_connections" => PerfMap::new(m, -1, 0, 16, || {
                let statsd = statsd.clone();
                Box::new(move |raw| {
                    use cadence::prelude::*;

                    let connection = Connection::from(_data_connect::from(raw));
                    let _sent = statsd
                        .incr_with_tags("connection.{}")
                        .with_tag("host", &format!("{}", connection.destination_ip))
                        .with_tag("port", &format!("{}", connection.destination_port))
                        .with_tag("name", &format!("{}", connection.name))
                        .try_send()
                        .unwrap();
                })
            }),
            "tcp4_volume" => PerfMap::new(m, -1, 0, 128, || {
                let statsd = statsd.clone();
                Box::new(move |raw| {
                    use cadence::prelude::*;
                    let volume = Volume::from(_data_volume::from(raw));

                    let vol = if volume.send > 0 {
                        volume.send
                    } else {
                        volume.recv
                    };
                    let _stat = statsd
                        .count_with_tags(
                            &format!("volume.{}", if volume.send > 0 { "out" } else { "in" }),
                            vol as i64,
                        )
                        .with_tag("host", &format!("{}", volume.connection.destination_ip))
                        .with_tag("port", &format!("{}", volume.connection.destination_port))
                        .with_tag("name", &format!("{}", volume.connection.name))
                        .with_tag("proto", "tcpv4")
                        .try_send()
                        .unwrap();
                })
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
