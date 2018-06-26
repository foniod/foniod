#![allow(non_camel_case_types)]

use grains::*;
use grains::connection::{Volume, _data_volume};
use redbpf::{LoadError, PerfMap};

use cadence::StatsdClient;

pub struct UDP;

const MODULE_UDP: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/udp.elf"));

impl<'m> EBPFModule<'static, 'm> for UDP {
    fn code() -> &'static [u8] {
        MODULE_UDP
    }

    fn handler(m: &'m mut Map, statsd: &StatsdClient) -> Result<PerfMap<'m>> {
        match m.name.as_str() {
            "udp_volume" => PerfMap::new(m, -1, 0, 128, || {
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
                        .with_tag("proto", "udp")
                        .try_send()
                        .unwrap();

                    println!("{:?}", volume)
                })
            }),
            _ => Err(LoadError::BPF),
        }
    }
}
