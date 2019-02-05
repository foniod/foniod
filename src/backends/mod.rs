use actix;
use serde_json;

use std::collections::HashMap;

pub mod console;
#[cfg(feature = "http-backend")]
pub mod http;
#[cfg(feature = "s3-backend")]
pub mod s3;
#[cfg(feature = "statsd-backend")]
pub mod statsd;

use crate::metrics::{kind::Kind, Measurement, Unit};

pub type BackendHandler = actix::Recipient<Message>;

#[derive(Message)]
pub struct Flush;

impl actix::Message for Measurement {
    type Result = ();
}

#[derive(Debug, Clone, Message)]
pub enum Message {
    Single(Measurement),
    List(Vec<Measurement>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedMeasurement {
    timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub measurement: u64,
    pub tags: HashMap<String, String>,
}

impl Message {
    fn to_string(mut self) -> String {
        match self {
            Message::List(ref mut lst) => format!(
                "[{}]",
                lst.drain(..)
                    .map(|msg| serde_json::to_string(&SerializedMeasurement::from(msg)).unwrap())
                    .collect::<Vec<String>>()
                    .join(",\n")
            ),
            Message::Single(msg) => {
                serde_json::to_string(&[SerializedMeasurement::from(msg)]).unwrap()
            }
        }
    }
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
