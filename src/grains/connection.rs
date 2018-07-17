#![allow(non_camel_case_types)]

use std::net::Ipv4Addr;
use std::ptr;

use grains::*;
use redbpf::PerfCallback;

include!(concat!(env!("OUT_DIR"), "/connection.rs"));

pub fn get_volume_callback(proto: &'static str, upstreams: Vec<BackendHandler>) -> PerfCallback {
    Box::new(move |raw| {
        let volume = Volume::from(_data_volume::from(raw));
        let name = format!("volume.{}", if volume.send > 0 { "out" } else { "in" });
        let mut tags = volume.connection.to_tags();

        tags.insert("proto".to_string(), proto.to_string());

        let vol = if volume.send > 0 {
            volume.send
        } else {
            volume.recv
        };

        send_to(
            &upstreams,
            Message::Single(Measurement::new(
                COUNTER | HISTOGRAM,
                name.clone(),
                Unit::Byte(vol as u64),
                tags.clone(),
            )),
        );
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
            name: to_string(unsafe { &*(&data.comm as *const [i8] as *const [u8]) }),
            source_ip: to_ip(data.saddr),
            destination_ip: to_ip(data.daddr),
            destination_port: to_le(data.dport),
            source_port: to_le(data.sport),
        }
    }
}
