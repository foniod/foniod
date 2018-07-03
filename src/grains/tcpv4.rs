#![allow(non_camel_case_types)]

use grains::connection::{Connection, Volume, _data_connect, _data_volume};
use grains::*;
use redbpf::{LoadError, PerfMap, Result};
use std::collections::HashMap;

use actix::Recipient;
use metrics::Measurement;

pub struct TCP4;

impl<'m> EBPFModule<'static, 'm> for TCP4 {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tcpv4.elf"))
    }

    fn handler(m: &'m mut Map, actor: &Recipient<Measurement>) -> Result<PerfMap<'m>> {
        match m.name.as_str() {
            "tcp4_connections" => PerfMap::new(m, -1, 0, 16, || {
                let actor = actor.clone();
                Box::new(move |raw| {
                    let name = "connection.out".to_string();

                    let connection = Connection::from(_data_connect::from(raw));
                    let mut tags = HashMap::new();

                    let dip = format!("{}", connection.destination_ip);
                    let dport = format!("{}", connection.destination_port);
                    let process = format!("{}", connection.name);
                    tags.insert("destination".to_string(), dip);
                    tags.insert("dport".to_string(), dport);
                    tags.insert("process".to_string(), process);

                    actor.do_send(Measurement::new(name, 1, None, tags));
                })
            }),
            "tcp4_volume" => PerfMap::new(m, -1, 0, 128, || {
                let actor = actor.clone();
                Box::new(move |raw| {
                    let volume = Volume::from(_data_volume::from(raw));
                    let mut tags = HashMap::new();

                    let unit = Some("byte".to_string());
                    let name = format!("volume.{}", if volume.send > 0 { "out" } else { "in" });
                    let dip = format!("{}", volume.connection.destination_ip);
                    let dport = format!("{}", volume.connection.destination_port);
                    let process = format!("{}", volume.connection.name);
                    tags.insert("destination".to_string(), dip);
                    tags.insert("dport".to_string(), dport);
                    tags.insert("process".to_string(), process);
                    tags.insert("proto".to_string(), "tcp4".to_string());

                    let vol = if volume.send > 0 {
                        volume.send
                    } else {
                        volume.recv
                    };
                    actor.do_send(Measurement::new(name, vol as i64, unit, tags));
                })
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
