#![allow(non_camel_case_types)]

use std::net::Ipv4Addr;
use std::ptr;

use grains::*;
use redbpf::PerfCallback;

include!(concat!(env!("OUT_DIR"), "/connection.rs"));

pub fn get_volume_callback(proto: &'static str, upstreams: Vec<Backend>) -> PerfCallback {
    Box::new(move |raw| {
        let volume = Volume::from(_data_volume::from(raw));

        let unit = Some("byte".to_string());
        let name = format!("volume.{}", if volume.send > 0 { "out" } else { "in" });

        let mut tags = volume.connection.to_tags();
        tags.insert("proto".to_string(), proto.to_string());

        let vol = if volume.send > 0 {
            volume.send
        } else {
            volume.recv
        };

        for upstream in upstreams.iter() {
            use metrics::kind::*;

            upstream.do_send(Measurement::new(
                COUNTER | HISTOGRAM,
                name.clone(),
                vol as i64,
                unit.clone(),
                tags.clone(),
            ));
        }
    })
}

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
    pub task_id: u64, 
    pub name: String,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
}

impl Connection {
    pub fn to_tags(&self) -> HashMap<String, String> {
        let mut tags = HashMap::new();

        tags.insert("process".to_string(), self.name.clone());
        tags.insert("task_id".to_string(), self.task_id.to_string());

        tags.insert("d_ip".to_string(), self.destination_ip.to_string());
        tags.insert("d_port".to_string(), self.destination_port.to_string());

        tags.insert("s_ip".to_string(), self.source_ip.to_string());
        tags.insert("s_port".to_string(), self.source_port.to_string());

        tags
    }
}

impl From<_data_connect> for Connection {
    fn from(data: _data_connect) -> Connection {
        Connection {
            task_id: data.id,
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
