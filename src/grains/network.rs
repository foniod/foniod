#![allow(non_camel_case_types)]

use crate::grains::{self, *};

use ingraind_probes::network::{Connection, Ipv6Addr, Message};
use redbpf_probes::bindings::{IPPROTO_TCP, IPPROTO_UDP};

use std::net;

pub struct Network;

impl EBPFProbe for Grain<Network> {
    fn attach(&mut self) -> MessageStreams {
        self.attach_kprobes()
    }
}

impl EBPFGrain<'static> for Network {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/ingraind-probes/target/release/bpf-programs/network/network.elf"
        ))
    }

    fn get_handler(&self, id: &str) -> EventCallback {
        match id {
            "ip_connections" => Box::new(|raw| {
                let event = unsafe { std::ptr::read(raw.as_ptr() as *const Connection) };

                Some(grains::Message::Single(Measurement::new(
                    COUNTER | HISTOGRAM | METER,
                    "connection.out".to_string(),
                    Unit::Count(1),
                    conn_tags(&event),
                )))
            }),

            "ip_volume" => Box::new(|raw| {
                let event = unsafe { std::ptr::read(raw.as_ptr() as *const Message) };
		let (name, conn, vol) = match event {
		    Message::Send(conn, size) => ("volume.out", conn, size),
		    Message::Receive(conn, size) => ("volume.in", conn, size)
		};

		let proto = match conn.typ {
		    IPPROTO_TCP => "tcp",
		    IPPROTO_UDP => "udp",
		    _ => return None
		};

		let mut tags = conn_tags(&conn);
		tags.insert("proto", proto);

                Some(grains::Message::Single(Measurement::new(
                    COUNTER | HISTOGRAM,
                    name.to_string(),
                    Unit::Byte(vol as u64),
                    tags,
                )))
            }),
            _ => unreachable!(),
        }
    }
}

fn conn_tags(event: &Connection) -> Tags {
    let mut tags = Tags::new();
    tags.insert("process_str", to_string(&event.comm));
    tags.insert("process_id", event.pid.to_string());
    tags.insert("d_ip", ip_to_string(&event.daddr));
    tags.insert("s_ip", ip_to_string(&event.saddr));
    tags.insert("d_port", to_le(event.dport as u16).to_string());
    tags.insert("s_port", to_le(event.sport as u16).to_string());
    
    tags
}

fn ip_to_string(addr: &Ipv6Addr) -> String {
    let v6: &std::net::Ipv6Addr = unsafe { std::mem::transmute(addr) };

    match v6.to_ipv4() {
	Some(v4) => v4.to_string(),
	None => v6.to_string()
    }
}
