use std::collections::HashMap;

use serde_json;

use super::{Kind, Measurement, Message, Unit};

#[derive(Serialize, Deserialize, Debug)]
pub enum Encoding {
    JSON,
    #[cfg(feature = "capnp")]
    Capnp,
}

pub type Encoder = Box<Fn(Message) -> Vec<u8>>;

impl Encoding {
    pub fn to_encoder(self) -> Encoder {
        Box::new(match self {
            Encoding::JSON => to_json,
            #[cfg(feature = "capnp")]
            Encoding::Capnp => to_capnp,
        })
    }
}

#[cfg(feature = "capnp-encoding")]
pub fn to_capnp(msg: Message) -> Vec<u8> {
    use std::io::Cursor;
    use capnp::serialize;
    use crate::ingraind_capnp::*;

    let mut src = match msg {
        Message::Single(m) => vec![m],
        Message::List(l) => l,
    };
    
    let mut message = ::capnp::message::Builder::new_default();
    let mut payload = message.init_root::<ingrain_payload::Builder>();

    let mut data = payload.init_data(src.len() as u32);
    for (i, mut source) in src.drain(..).enumerate() {
        let mut m = data.reborrow().get(i as u32);
        m.set_timestamp(source.timestamp);
        m.set_kind(source.kind);
        m.set_name(&source.name);
        m.set_measurement(source.value.get() as f64);

        let mut tags = m.init_tags(source.tags.0.len() as u32);
        for (i, mut source) in source.tags.0.drain(..).enumerate() {
            let mut tag = tags.reborrow().get(i as u32);
            tag.set_key(&source.0);
            tag.set_value(&source.1);
        }
    }

    let mut buffer = Cursor::new(Vec::new());
    serialize::write_message(&mut buffer, &message);
    buffer.into_inner()
}

pub fn to_json(mut msg: Message) -> Vec<u8> {
    match msg {
        Message::List(ref mut lst) => serde_json::to_vec(
            &lst.drain(..)
                .map(SerializedMeasurement::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
        Message::Single(msg) => serde_json::to_vec(&[SerializedMeasurement::from(msg)]).unwrap(),
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SerializedMeasurement {
    timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub measurement: u64,
    pub tags: HashMap<String, String>,
}

impl From<Measurement> for SerializedMeasurement {
    fn from(mut msg: Measurement) -> SerializedMeasurement {
        let (type_str, measurement) = match msg.value {
            Unit::Byte(x) => ("byte", x),
            Unit::Count(x) => ("count", x),
        };

        let name = format!("{}_{}", &msg.name, type_str);

        SerializedMeasurement {
            timestamp: msg.timestamp,
            kind: msg.kind,
            name,
            measurement,
            tags: msg.tags.drain(..).collect(),
        }
    }
}
