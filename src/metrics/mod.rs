use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Tags = HashMap<String, String>;

pub mod kind {
    pub type Kind = u16;
    pub const COUNTER: Kind = 1;
    pub const GAUGE: Kind = 2;
    pub const METER: Kind = 4;
    pub const HISTOGRAM: Kind = 8;
}

use self::kind::Kind;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Unit {
    #[serde(rename = "byte")]
    Byte(u64),
    #[serde(rename = "count")]
    Count(u64),
}

impl Unit {
    pub fn get(&self) -> u64 {
        use self::Unit::*;

        match *self {
            Byte(x) | Count(x) => x,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Measurement {
    pub timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub value: Unit,
    pub tags: Tags,
}

impl Measurement {
    pub fn new(kind: Kind, name: String, value: Unit, tags: Tags) -> Self {
        Self {
            timestamp: timestamp_now(),
            kind,
            name,
            value,
            tags,
        }
    }
}

pub fn timestamp_now() -> u64 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    duration.as_secs() * (1e9 as u64) + duration.subsec_nanos() as u64
}
