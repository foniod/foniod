use std::convert::TryInto;
use std::os::raw::c_char;

use crate::grains::protocol::ip::to_ipv4;
use crate::grains::*;

use dns_parser::{rdata::RData, Packet};

use ingraind_probes::dns::Event;

pub struct DNS(pub DnsConfig);
#[derive(Serialize, Deserialize, Debug)]
pub struct DnsConfig {
    interface: String,
}

impl EBPFProbe for Grain<DNS> {
    fn attach(&mut self) -> MessageStreams {
        let iface = self.native.0.interface.clone();
        self.attach_xdps(iface.as_str())
    }
}

impl EBPFGrain<'static> for DNS {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/ingraind-probes/target/release/bpf-programs/dns/dns.elf"
        ))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(|raw| {
            let event = unsafe { &*(raw.as_ptr() as *const Event) };
            if let Ok(packet) = Packet::parse(event.data()) {
                let query = DNSQuery::from(event);
                let mut tags = query.to_tags();

                tags.insert(
                    "q_address_str",
                    packet.questions
                        .iter()
                        .map(|v| v.qname.to_string())
                        .collect::<Vec<String>>()
                        .join(","),
                );
                tags.insert(
                    "q_answer_ip_list",
                    packet.answers
                        .iter()
			.filter(|v| match v.data {
			    RData::Unknown(_) => false,
			    _ => true
			})
                        .map(|v| format!("{:?}", v.data))
                        .collect::<Vec<String>>()
                        .join(","),
                );

                Some(Message::Single(Measurement::new(
                    COUNTER | HISTOGRAM | METER,
                    "dns.answer".to_string(),
                    Unit::Count(1),
                    tags,
                )))
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DNSQuery {
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
}

impl From<&Event> for DNSQuery {
    fn from(event: &Event) -> DNSQuery {
        DNSQuery {
            destination_ip: to_ipv4(event.daddr),
            source_ip: to_ipv4(event.saddr),
            destination_port: event.dport,
            source_port: event.sport,
        }
    }
}

impl ToTags for DNSQuery {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("d_ip", self.destination_ip.to_string());
        tags.insert("d_port", self.destination_port.to_string());

        tags.insert("s_ip", self.source_ip.to_string());
        tags.insert("s_port", self.source_port.to_string());

        tags
    }
}
