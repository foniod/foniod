use std::ops::RangeBounds;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Drain;
use std::hash::Hash;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tags(pub Vec<(String, String)>);

impl Tags {
    pub fn new() -> Tags {
        Tags(Vec::with_capacity(16))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn insert(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.0.push((k.into(), v.into()));
    }

    pub fn append(&mut self, other: &mut Tags) {
        self.0.append(&mut other.0);
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, String)> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (String, String)> {
        self.0.iter_mut()
    }

    pub fn drain<R>(&mut self, r: R) -> Drain<(String, String)>
    where
        R: RangeBounds<usize>,
    {
        self.0.drain(r)
    }

    pub fn get(&self, k: impl Into<String>) -> Option<&str> {
        let ks = k.into();
        self.0.iter().find_map(|(tk, tv)| {
            if tk == &ks {
                Some(tv.as_str())
            } else {
                None
            }
        })
    }
}

pub trait ToTags {
    fn to_tags(self) -> Tags;
}

impl ToTags for Tags {
    fn to_tags(self) -> Tags {
        self
    }
}

pub mod kind {
    pub type Kind = u16;
    pub const COUNTER: Kind = 1;
    pub const GAUGE: Kind = 2;
    pub const METER: Kind = 4;
    pub const HISTOGRAM: Kind = 8;
    pub const TIMER: Kind = 16;
    pub const SET: Kind = 32;
    pub const SET_UNIQUES: Kind = 64;
    pub const PERCENTILE: Kind = 128;

    pub fn try_from_str(s: &str) -> Result<Kind, ()> {
        let k = match s.to_uppercase().as_str() {
            "COUNTER" => COUNTER,
            "GAUGE" => GAUGE,
            "METER" => METER,
            "HISTOGRAM" => HISTOGRAM,
            "TIMER" => TIMER,
            "SET" => SET,
            "SET_UNIQUES" => SET_UNIQUES,
            "PERCENTILE" => PERCENTILE,
            _ => return Err(())
        };

        Ok(k)
    }
}

use self::kind::Kind;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    #[serde(rename = "byte")]
    Byte(u64),
    #[serde(rename = "count")]
    Count(u64),
    #[serde(rename = "string")]
    Str(String)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum UnitType {
    Byte,
    Count,
    Str
}

impl UnitType {
    pub fn to_unit(self, val: u64) -> Unit {
        use UnitType::*;

        match self {
            Byte => Unit::Byte(val),
            Count => Unit::Count(val),
            _ => panic!("Invalid conversion")
        }
    }

    pub fn to_unit_str(self, val: String) -> Unit {
        Unit::Str(val)
    }
}

impl Unit {
    pub fn get(&self) -> u64 {
        use self::Unit::*;

        match *self {
            Byte(x) | Count(x) => x,
            Str(_) =>  {
                debug!("get() called on string metric");
                0
            }
        }
    }

    pub fn get_type(&self) -> UnitType {
        use Unit::*;

        match *self {
            Byte(_) => UnitType::Byte,
            Count(_) => UnitType::Count,
            Str(_) => UnitType::Str,
        }
    }

    pub fn try_from_str(s: &str, val: u64) -> Result<Unit, ()> {
        use Unit::*;

        let u = match s.to_uppercase().as_str() {
            "BYTE" => Byte(val),
            "COUNT" => Count(val),
            _ => return Err(())
        };

        Ok(u)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Measurement {
    pub timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub value: Unit,
    pub sample_rate: Option<f64>,
    pub reset: bool,
    pub tags: Tags,
}

impl Measurement {
    pub fn new(kind: Kind, name: String, value: Unit, tags: Tags) -> Self {
	Self::with_timestamp(timestamp_now(), kind, name, value, tags)
    }

    pub fn with_timestamp(timestamp: u64, kind: Kind, name: String, value: Unit, tags: Tags) -> Self {
        Self {
            timestamp,
            kind,
            name,
            value,
            sample_rate: Some(1.0),
            reset: true,
            tags,
        }
    }
}

pub fn timestamp_now() -> u64 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    duration.as_secs() * (1e9 as u64) + u64::from(duration.subsec_nanos())
}
