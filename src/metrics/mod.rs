use std::collections::HashMap;
use std::time::Instant;
use serde_millis;

pub type Tags = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug)]
pub struct Measurement {
    #[serde(with = "serde_millis")]
    timestamp: Instant,
    pub name: String,
    pub value: u64,
    pub unit: Option<String>,
    pub tags: Tags,
}

impl Measurement {
    fn new(name: String, value: u64, unit: Option<String>, tags: Tags) -> Self {
        Self {
            timestamp: Instant::now(),
            name,
            value,
            unit,
            tags,
        }
    }
}
