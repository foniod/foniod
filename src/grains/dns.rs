use crate::grains::protocol::ip::to_ipv4;
use crate::grains::*;
use crate::metrics::timestamp_now;

use dns_parser::{rdata::RData, Packet, ResourceRecord};
use metrohash::MetroHash64;
use std::hash::Hasher;

use ingraind_probes::dns::{MapData, Event};

pub struct DNS(pub DnsConfig);
#[derive(Serialize, Deserialize, Debug)]
pub struct DnsConfig {
    interface: String,
    #[serde(default = "default_xdp_mode")]
    xdp_mode: XdpMode
}

impl EBPFProbe for Grain<DNS> {
    fn attach(&mut self) -> MessageStreams {
        let conf = &self.native.0;
        let interface = conf.interface.clone();
        let flags = conf.xdp_mode.into();
        self.attach_xdps(&interface, flags)
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
            let data = unsafe { &*(raw.as_ptr() as *const MapData<Event>) };
            let event = &data.data;
            if let Ok(packet) = Packet::parse(data.payload()) {
                let timestamp = timestamp_now();
                let query = DNSQuery::from(event);

                let mut tags = query.to_tags();
                let id = hash_event(event, timestamp);

                tags.insert("id", &id);

                let mut measurements = vec![Measurement::with_timestamp(
                    timestamp,
                    COUNTER | HISTOGRAM | METER,
                    "dns.answer".to_string(),
                    Unit::Count(1),
                    tags,
                )];

                measurements.extend(
                    packet
                        .questions
                        .iter()
                        .map(|v| {
                            Measurement::with_timestamp(
                                timestamp,
                                COUNTER | HISTOGRAM | METER,
                                "dns.answer_address".to_string(),
                                Unit::Count(1),
                                Tags(vec![
                                    ("q_address_str".to_string(), v.qname.to_string()),
                                    ("id".to_string(), id.clone()),
                                ]),
                            )
                        })
                        .collect::<Vec<Measurement>>(),
                );

                measurements.extend(
                    packet
                        .answers
                        .iter()
                        .filter(|v| match v.data {
                            RData::Unknown(_) => false,
                            _ => true,
                        })
                        .map(|v| {
                            Measurement::with_timestamp(
                                timestamp,
                                COUNTER | HISTOGRAM | METER,
                                "dns.answer_record".to_string(),
                                Unit::Count(1),
                                ip_to_tags(v, &id),
                            )
                        })
                        .collect::<Vec<Measurement>>(),
                );

                Some(Message::List(measurements))
            } else {
                None
            }
        })
    }
}

fn hash_event(event: &Event, timestamp: u64) -> String {
    let mut hasher = MetroHash64::new();

    hasher.write_u64(timestamp);
    hasher.write_u32(event.saddr);
    hasher.write_u32(event.daddr);
    hasher.write_u16(event.sport);
    hasher.write_u16(event.dport);

    hasher.finish().to_string()
}

fn ip_to_tags(v: &ResourceRecord, id: &str) -> Tags {
    use RData::*;

    let mut tags = Tags::new();
    tags.insert("id", id.clone());

    match &v.data {
        A(a) => {
            tags.insert("record_type", "A");
            tags.insert("address", a.0.to_string());
        }
        AAAA(aaaa) => {
            tags.insert("record_type", "AAAA");
            tags.insert("address", aaaa.0.to_string());
        }
        CNAME(cname) => {
            tags.insert("record_type", "CNAME");
            tags.insert("address", cname.0.to_string());
        }
        MX(mx) => {
            tags.insert("record_type", "MX");
            tags.insert("mx_preference", format!("{}", mx.preference));
            tags.insert("address", mx.exchange.to_string());
        }
        NS(ns) => {
            tags.insert("record_type", "NS");
            tags.insert("address", ns.0.to_string());
        }
        PTR(ptr) => {
            tags.insert("record_type", "PTR");
            tags.insert("address", ptr.0.to_string());
        }
        SOA(soa) => {
            tags.insert("record_type", "SOA");
            tags.insert("primary_ns", soa.primary_ns.to_string());
            tags.insert("mailbox", soa.mailbox.to_string());
            tags.insert("serial", format!("{}", soa.serial));
            tags.insert("refresh", format!("{}", soa.refresh));
            tags.insert("retry", format!("{}", soa.retry));
            tags.insert("expire", format!("{}", soa.expire));
            tags.insert("minimum_ttl", format!("{}", soa.minimum_ttl));
        }
        SRV(srv) => {
            tags.insert("record_type", "SRV");
            tags.insert("srv_priority", format!("{}", srv.priority));
            tags.insert("srv_weight", format!("{}", srv.weight));
            tags.insert("srv_port", format!("{}", srv.port));
            tags.insert("address", srv.target.to_string());
        }
        TXT(_txt) => {
            tags.insert("record_type", "TXT");
	    // ignore txt responses for now because of potential size
	    // and encoding issues
        }
	Unknown(_) => unreachable!()
    };

    tags
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
