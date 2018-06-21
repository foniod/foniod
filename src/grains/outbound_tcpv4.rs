use grains::Grain;
use redbpf::{LoadError, Module, PerfMap};
use serde::{Deserialize, Serialize};

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::ptr;
use std::thread;
use std::time::Duration;

pub struct OutboundTCP4;

impl Grain for OutboundTCP4 {
    fn start() {
        // let mut f = File::open(env::var("MOD").unwrap()).unwrap();
        // let mut bytes = vec![];
        // f.read_to_end(&mut bytes);

        // let mut module = Module::parse(&mut bytes).unwrap();
        let mut module = Module::parse(OUTBOUND_TCPV4).unwrap();

        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
            println!(
                "prog loaded: {} {} {:?}",
                prog.attach().is_ok(),
                prog.name,
                prog.kind
            );
        }

        let mut perfmaps: Vec<PerfMap> = module
            .maps
            .iter_mut()
            .map(|m| {
                PerfMap::new(m, -1, 0, 16, || {
                    Box::new(|raw| {
                        let lowlevel = _data_connect::from(raw);
                        let connection = Connection::from(lowlevel);
                        println!("{:?}", connection);
                    })
                }).unwrap()
            })
            .collect();

        loop {
            thread::sleep(Duration::from_secs(1));

            for pm in perfmaps.iter_mut() {
                pm.poll(100)
            }
        }
    }
}

#[allow(non_camel_case_types)]
const OUTBOUND_TCPV4: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/outbound_tcpv4.elf"));
include!(concat!(env!("OUT_DIR"), "/outbound_tcpv4.rs"));

#[derive(Debug, Serialize, Deserialize)]
struct Connection {
    pid: u32,
    name: String,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    destination_port: u16,
}

impl From<_data_connect> for Connection {
    fn from(data: _data_connect) -> Connection {
        Connection {
            pid: data.id as u32,
            name: get_string(unsafe { &*(&data.comm as *const [i8] as *const [u8]) }),
            source_ip: to_ip(data.saddr),
            destination_ip: to_ip(data.daddr),
            destination_port: data.dport,
        }
    }
}

fn to_ip(bytes: u32) -> Ipv4Addr {
    let d = (bytes >> 24) as u8;
    let c = (bytes >> 16) as u8;
    let b = (bytes >> 8) as u8;
    let a = bytes as u8;

    Ipv4Addr::new(a, b, c, d)
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}
