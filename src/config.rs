use std::collections::HashMap;

use actix::Recipient;

use aggregations::*;
use backends::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    probe: HashMap<String, Probe>,
    pipeline: HashMap<String, Pipeline>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Probe {
    pipeline: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pipeline {
    config: Backend,
    steps: Vec<Aggregator>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Backend {
    S3(S3Config),
    Statsd(StatsdConfig),
    Console,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct S3Config;

#[derive(Serialize, Deserialize, Debug)]
pub struct StatsdConfig {
    use_tags: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BufferConfig {
    pub interval_s: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Aggregator {
    AddSystemDetails,
    Buffer(BufferConfig),
}

impl Aggregator {
    pub fn into_recipient(&self, upstream: Recipient<Message>) -> Recipient<Message> {
        match *self {
            Aggregator::AddSystemDetails => AddSystemDetails::launch(upstream),
            Aggregator::Buffer(ref config) => Buffer::launch(config, upstream),
        }
    }
}

mod tests {
    #[test]
    fn can_parse() {
        use config::Config;
        use toml;

        let config: Config = toml::from_str(
            r#"
[probe.tcp4]
pipeline = ["statsd"]

[probe.udp]
pipeline = ["statsd"]

[pipeline.statsd.config]
type = "Statsd"
use_tags = true

[[pipeline.statsd.steps]]
type = "AddSystemDetails"

[[pipeline.statsd.steps]]
type = "Holdback"
interval_s = 30
"#,
        ).unwrap();
    }
}
