use std::collections::HashMap;

use serde_json;

use capnp;
use crate::ingraind_capnp;
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

pub fn to_capnp(msg: Message) -> Vec<u8> {
    vec![]
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
