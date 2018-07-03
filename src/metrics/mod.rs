use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Tags = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Measurement {
    timestamp: u64,
    pub name: String,
    pub value: i64,
    pub unit: Option<String>,
    pub tags: Tags,
}

impl Measurement {
    pub fn new(name: String, value: i64, unit: Option<String>, tags: Tags) -> Self {
        Self {
            timestamp: {
                let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                duration.as_secs() * (1e9 as u64) + duration.subsec_nanos() as u64
            },
            name,
            value,
            unit,
            tags,
        }
    }
}
