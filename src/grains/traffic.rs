use crate::grains::protocol::ip::to_ipv4;
use crate::grains::*;

include!(concat!(env!("OUT_DIR"), "/router.rs"));

pub struct TrafficCounter(pub TrafficCounterConfig);
#[derive(Serialize, Deserialize, Debug)]
pub struct TrafficCounterConfig {
    interface: String,
}

impl EBPFProbe for Grain<TrafficCounter> {
    fn attach(&mut self) -> MessageStreams {
        let iface = self.native.0.interface.clone();
        self.attach_xdps(iface.as_str())
    }
}

impl EBPFGrain<'static> for TrafficCounter {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/router.elf"))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(|raw| {
            let traffic = Traffic::from(_data_exchange::from(raw));
            let tags = traffic.clone().to_tags();

            Some(Message::Single(Measurement::new(
                COUNTER | HISTOGRAM | METER,
                format!("volume.{}", match traffic.protocol {
                    17 => "udp",
                    6 => "tcp",
                    _ => "unknown"
                }),
                Unit::Byte(traffic.size as u64),
                tags,
            )))
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Traffic {
    pub size: u16,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub protocol: u8
}

impl From<_data_exchange> for Traffic {
    fn from(data: _data_exchange) -> Traffic {
        Traffic {
            destination_ip: to_ipv4(data.daddr),
            source_ip: to_ipv4(data.saddr),
            destination_port: data.dport,
            source_port: data.sport,
            size: data.size as u16,
            protocol: data.proto
        }
    }
}

impl ToTags for Traffic {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("d_ip", self.destination_ip.to_string());
        tags.insert("d_port", self.destination_port.to_string());

        tags.insert("s_ip", self.source_ip.to_string());
        tags.insert("s_port", self.source_port.to_string());

        tags
    }
}
