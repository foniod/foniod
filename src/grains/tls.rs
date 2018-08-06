#![allow(non_camel_case_types)]

use grains::*;
use grains::protocol::ETH_HLEN;
use metrics::Tags;

use rustls::internal::msgs::{
    codec::Codec, enums::ContentType, enums::ServerNameType, handshake::ClientHelloPayload,
    handshake::HandshakePayload, handshake::HasServerExtensions, handshake::ServerHelloPayload,
    handshake::ServerNamePayload, message::Message as TLSMessage, message::MessagePayload,
};
use rustls::CipherSuite;

use std::net::Ipv4Addr;

pub struct TLS;

impl EBPFGrain<'static> for TLS {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/tls.elf"))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(|raw| tls_to_message(raw))
    }
}

fn tls_to_message(buf: &[u8]) -> Option<Message> {
    let handshake = {
        let offset = tcp_payload_offset(buf);
        let mut packet = TLSMessage::read_bytes(&buf[offset..])?;

        if packet.typ == ContentType::Handshake && packet.decode_payload() {
            if let MessagePayload::Handshake(x) = packet.payload {
                x
            } else {
                return None;
            }
        } else {
            return None;
        }
    };

    let tags = tag_ip_and_ports(buf);

    use self::HandshakePayload::*;
    match handshake.payload {
        ClientHello(payload) => parse_clienthello(payload, tags),
        ServerHello(payload) => parse_serverhello(payload, tags),
        _ => None,
    }
}

fn parse_clienthello(payload: ClientHelloPayload, mut tags: Tags) -> Option<Message> {
    tags.insert(
        "ciphersuites_list",
        cipher_suites_to_string(&payload.cipher_suites),
    );

    if let Some(ref sni) = payload.get_sni_extension() {
        tags.insert(
            "sni_list",
            sni.iter()
                .filter(|sni| sni.typ == ServerNameType::HostName)
                .map(|sni| match &sni.payload {
                    ServerNamePayload::HostName(dnsn) => format!("{}", AsRef::<str>::as_ref(&dnsn)),
                    _ => unreachable!(),
                })
                .collect::<Vec<String>>()
                .join(","),
        );
    }

    msg("clienthello", tags)
}

fn parse_serverhello(payload: ServerHelloPayload, mut tags: Tags) -> Option<Message> {
    tags.insert("ciphersuite_str", format!("{:?}", payload.cipher_suite));
    if let Some(proto) = payload.get_alpn_protocol() {
        tags.insert("alpn_str", proto);
    }

    msg("serverhello", tags)
}

fn cipher_suites_to_string(list: &[CipherSuite]) -> String {
    list.iter()
        .map(|v| format!("{:?}", v))
        .collect::<Vec<String>>()
        .join(",")
}

fn tag_ip_and_ports(buf: &[u8]) -> Tags {
    let mut tags = Tags::new();

    let (d_ip, s_ip) = parse_ips(buf);
    let (d_port, s_port) = parse_tcp_ports(buf);

    tags.insert("d_ip", d_ip);
    tags.insert("s_ip", s_ip);
    tags.insert("d_port", d_port.to_string());
    tags.insert("s_port", s_port.to_string());

    tags
}

fn parse_ips(buf: &[u8]) -> (String, String) {
    let s = Ipv4Addr::new(
        buf[ETH_HLEN + 12],
        buf[ETH_HLEN + 13],
        buf[ETH_HLEN + 14],
        buf[ETH_HLEN + 15],
    );

    let d = Ipv4Addr::new(
        buf[ETH_HLEN + 16],
        buf[ETH_HLEN + 17],
        buf[ETH_HLEN + 18],
        buf[ETH_HLEN + 19],
    );

    (d.to_string(), s.to_string())
}

fn parse_tcp_ports(buf: &[u8]) -> (u16, u16) {
    let offs = ETH_HLEN + iph_len(buf);
    let s: u16 = (buf[offs + 0] as u16) << 8 | buf[offs + 1] as u16;
    let d: u16 = (buf[offs + 2] as u16) << 8 | buf[offs + 3] as u16;

    (d, s)
}

#[inline]
fn iph_len(buf: &[u8]) -> usize {
    ((buf[ETH_HLEN] & 0x0F) as usize) << 2
}

#[inline]
fn tcp_len(buf: &[u8]) -> usize {
    ((buf[ETH_HLEN + iph_len(buf) + 12] as usize) >> 4) << 2
}

#[inline]
fn tcp_payload_offset(buf: &[u8]) -> usize {
    ETH_HLEN + iph_len(buf) + tcp_len(buf)
}

#[inline]
fn msg(name: &str, tags: Tags) -> Option<Message> {
    Some(Message::Single(Measurement::new(
        COUNTER | METER,
        format!("tls.handshake.{}", name),
        Unit::Count(1),
        tags,
    )))
}
