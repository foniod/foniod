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
pub struct Measurement {
    timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub value: i64,
    pub unit: Option<String>,
    pub tags: Tags,
}

impl Measurement {
    pub fn new(kind: Kind, name: String, value: i64, unit: Option<String>, tags: Tags) -> Self {
        Self {
            timestamp: nano_timestamp_now(),
            kind,
            name,
            value,
            unit,
            tags,
        }
    }
}

pub fn nano_timestamp_now() -> u64 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    duration.as_secs() * (1e9 as u64) + duration.subsec_nanos() as u64
}
