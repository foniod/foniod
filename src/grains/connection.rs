use std::net::Ipv4Addr;

use crate::grains::protocol::ip::to_ipv4;
use crate::grains::*;

include!(concat!(env!("OUT_DIR"), "/connection.rs"));

pub fn get_volume_callback(proto: &'static str) -> EventCallback {
    Box::new(move |raw| {
        let mut volume = Volume::from(_data_volume::from(raw));
        let name = format!("volume.{}", if volume.send > 0 { "out" } else { "in" });
        volume.connection.proto = proto.to_string();

        let tags = volume.connection.to_tags();
        let vol = if volume.send > 0 {
            volume.send
        } else {
            volume.recv
        };

        Some(Message::Single(Measurement::new(
            COUNTER | HISTOGRAM,
            name,
            Unit::Byte(vol as u64),
            tags,
        )))
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
    pub proto: String,
}

impl ToTags for Connection {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("process", self.name.as_str());
        tags.insert("task_id", self.task_id.to_string());

        tags.insert("d_ip", self.destination_ip.to_string());
        tags.insert("d_port", self.destination_port.to_string());

        tags.insert("s_ip", self.source_ip.to_string());
        tags.insert("s_port", self.source_port.to_string());

        tags.insert("proto", self.proto);

        tags
    }
}

impl From<_data_connect> for Connection {
    fn from(data: _data_connect) -> Connection {
        Connection {
            task_id: data.id,
            name: to_string(unsafe { &*(&data.comm as *const [i8] as *const [u8]) }),
            source_ip: to_ipv4(data.saddr),
            destination_ip: to_ipv4(data.daddr),
            destination_port: to_le(data.dport),
            source_port: to_le(data.sport),
            proto: "".to_string(),
        }
    }
}
