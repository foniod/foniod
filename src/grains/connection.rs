#![allow(non_camel_case_types)]

use std::net::Ipv4Addr;
use std::ptr;

include!(concat!(env!("OUT_DIR"), "/connection.rs"));

#[derive(Debug, Serialize, Deserialize)]
pub struct Volume {
    pub connection: Connection,
    pub send: usize,
    pub recv: usize,
}

impl From<_data_volume> for Volume {
    fn from(data: _data_volume) -> Volume {
        Volume {
            connection: Connection::from(data.conn),
            send: data.send,
            recv: data.recv,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub pid: u32,
    pub name: String,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub source_port: u16,
}

impl From<_data_connect> for Connection {
    fn from(data: _data_connect) -> Connection {
        Connection {
            pid: data.id as u32,
            name: get_string(unsafe { &*(&data.comm as *const [i8] as *const [u8]) }),
            source_ip: to_ip(data.saddr),
            destination_ip: to_ip(data.daddr),
            destination_port: (data.dport >> 8) | (data.dport << 8),
            source_port: (data.sport >> 8) | (data.sport << 8),
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
