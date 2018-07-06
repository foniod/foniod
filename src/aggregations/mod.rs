use std::collections::{BTreeMap, HashMap};

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
pub struct HoldbackConfig {
    interval_s: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Aggregator {
    AddHostname,
    AddKernel,
    Holdback(HoldbackConfig),
}

mod tests {
    #[test]
    fn can_parse() {
        use aggregations::*;
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
type = "AddKernel"

[[pipeline.statsd.steps]]
type = "AddHostname"

[[pipeline.statsd.steps]]
type = "Holdback"
interval_s = 30
"#,
        ).unwrap();

        // assert_eq!(config,
        //            Config { probe: {"udp": Probe { pipeline: ["statsd"] },
        //                             "tcp4": Probe { pipeline: ["statsd"] }},
        //                     pipeline: {"statsd": Pipeline { config: Statsd(StatsdConfig { use_tags: true }),
        //                                                     steps: [AddKernel,
        //                                                             AddHostname,
        //                                                             Holdback(HoldbackConfig { interval_s: 30 })
        //                                                     ] }}}
        // );
    }
}
