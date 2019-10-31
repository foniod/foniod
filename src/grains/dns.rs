use std::os::raw::c_char;
use std::convert::TryInto;

use crate::grains::protocol::ip::to_ipv4;
use crate::grains::*;

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
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ingraind-probes/target/release/bpf-programs/dns/dns.elf"))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(|raw| {
            let event = unsafe { &*(raw.as_ptr() as *const Event) };
            let query = DNSQuery::from(event);
            let tags = query.to_tags();

            Some(Message::Single(Measurement::new(
                COUNTER | HISTOGRAM | METER,
                "dns.answer".to_string(),
                Unit::Count(1),
                tags,
            )))
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DNSQuery {
    pub id: u16,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub address: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl From<&Event> for DNSQuery {
    fn from(event: &Event) -> DNSQuery {
        let query = parse_query(event.data()).unwrap();
        let question = &query.questions[0];
        DNSQuery {
            id: query.header.id,
            destination_ip: to_ipv4(event.daddr),
            source_ip: to_ipv4(event.saddr),
            destination_port: event.dport,
            source_port: event.sport,
            address: join(question.names.iter(), ".").unwrap(),
            qtype: question.query_type,
            qclass: question.query_class
        }
    }
}

impl ToTags for DNSQuery {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("q_dnstype", self.qtype.to_string());
        tags.insert("q_dnsclass", self.qclass.to_string());
        tags.insert("q_dnsid", self.id.to_string());

        tags.insert("q_domain_str", self.address.to_string());

        tags.insert("d_ip", self.destination_ip.to_string());
        tags.insert("d_port", self.destination_port.to_string());

        tags.insert("s_ip", self.source_ip.to_string());
        tags.insert("s_port", self.source_port.to_string());

        tags
    }
}

#[derive(Debug)]
enum Error {
    NeedMore,
    InvalidName
}

#[derive(Debug)]
struct Header {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16
}

enum PacketType {
    Query,
    Answer
}

#[derive(Debug)]
struct Query {
    header: Header,
    questions: Vec<Question>
}

#[derive(Debug)]
struct Question {
    names: Vec<String>,
    query_type: u16,
    query_class: u16
}

impl Header {
    fn packet_type(&self) -> PacketType {
        use PacketType::*;

        if self.flags & 1 << 15 == 0 {
            Query
        } else {
            Answer
        }
    }
}

fn parse_header(data: &[u8]) -> Result<Header, Error> {
    use Error::*;

    if data.len() < 12 {
        return Err(NeedMore)
    }

    let id = u16::from_be_bytes(data[..2].try_into().unwrap());
    let flags = u16::from_be_bytes(data[2..4].try_into().unwrap());
    let qd_count = u16::from_be_bytes(data[4..6].try_into().unwrap());
    let an_count = u16::from_be_bytes(data[6..8].try_into().unwrap());
    let ns_count = u16::from_be_bytes(data[8..10].try_into().unwrap());
    let ar_count = u16::from_be_bytes(data[10..12].try_into().unwrap());

    Ok(Header {
        id,
        flags,
        qd_count,
        an_count,
        ns_count,
        ar_count
    })
}

fn len_value(data: &[u8]) -> Option<(usize, &[u8])> {
    if !data.is_empty() {
        let len = data[0] as usize;
        if data.len() >= 1 + len {
            return Some((len, &data[1..1 + len]))
        }
    }

    None
}

fn parse_query(data: &[u8]) -> Result<Query, Error> {
    use Error::*;

    let header = parse_header(&data)?;
    let mut data = &data[12..];
    let mut questions = Vec::new();
    while questions.len() < header.qd_count as usize {
        if data.is_empty() {
            return Err(NeedMore)
        }

        let mut names = Vec::new();
        while data[0] != 0 {
            let (len, name) = len_value(data)
                .ok_or(NeedMore)
                .and_then(|(l, n)| {
                    Ok((
                        l,
                        String::from_utf8(n.to_vec()).map_err(|_| InvalidName)?
                    ))
                })?;
            names.push(name);
            data = &data[1 + len..];
            if data.is_empty() {
                return Err(NeedMore)
            }
        }
        if data.len() < 4 {
            return Err(NeedMore)
        }
        let query_type = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let query_class = u16::from_be_bytes(data[2..4].try_into().unwrap());

        questions.push(Question {
            names,
            query_type,
            query_class
        });
    }

    Ok(Query {
        header,
        questions
    })
}

fn join<T: Into<String>, I: Iterator<Item = T>>(mut iter: I, sep: &str) -> Option<String> {
    if let Some(item) = iter.next() {
        let mut ret = item.into();
        for item in iter {
            ret.push_str(sep);
            ret.push_str(&item.into());
        }
        return Some(ret);
    }

    None
}