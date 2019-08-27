use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::time::Duration;

use actix::utils::IntervalFunc;
use actix::{Actor, ActorStream, Context, ContextFutureSpawner, Handler, Recipient};
use hdrhistogram::Histogram;

use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit};

const PERCENTILES: [f64; 6] = [25f64, 50f64, 75f64, 90f64, 95f64, 99f64];

#[derive(Debug, Clone, PartialEq)]
struct AggregatedMetric<T: PartialEq> {
    value: T,
    tags: Tags,
}

#[derive(Debug)]
struct Aggregator {
    counters: HashMap<String, AggregatedMetric<f64>>,
    gauges: HashMap<String, AggregatedMetric<f64>>,
    timers: HashMap<String, AggregatedMetric<Vec<f64>>>,
    sets: HashMap<String, AggregatedMetric<HashSet<String>>>,
    histograms: HashMap<String, AggregatedMetric<Histogram<u64>>>,
}

impl Aggregator {
    pub fn new() -> Self {
        Aggregator {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            timers: HashMap::new(),
            sets: HashMap::new(),
            histograms: HashMap::new(),
        }
    }

    pub fn record<T: Into<Measurement>>(&mut self, measurement: T) {
        use kind::*;

        let Measurement {
            kind,
            name,
            value,
            sample_rate,
            reset,
            mut tags,
            ..
        } = measurement.into();

        let v = match kind {
            COUNTER | GAUGE | TIMER => value.get() as f64,
            _ => 0f64,
        };

        let key = name;
        match kind {
            kind::COUNTER => {
                let am = self
                    .counters
                    .entry(key)
                    .or_insert_with(|| AggregatedMetric {
                        value: 0f64,
                        tags: Tags::new(),
                    });
                am.value += v / sample_rate.unwrap_or(1.0);
                am.tags.append(&mut tags);
            }
            kind::GAUGE => {
                let am = self.gauges.entry(key).or_insert_with(|| AggregatedMetric {
                    value: 0f64,
                    tags: Tags::new(),
                });
                if reset {
                    am.value = v;
                } else {
                    am.value += v;
                }
                am.tags.append(&mut tags);
            }
            kind::TIMER => {
                let am = self.timers.entry(key).or_insert_with(|| AggregatedMetric {
                    value: Vec::new(),
                    tags: Tags::new(),
                });
                am.value.push(v);
                am.tags.append(&mut tags);
            }
            kind::SET => {
                let am = self.sets.entry(key).or_insert_with(|| AggregatedMetric {
                    value: HashSet::new(),
                    tags: Tags::new(),
                });
                if let Unit::Str(v) = value {
                    am.value.insert(v);
                }
                am.tags.append(&mut tags);
            }
            kind::HISTOGRAM => {
                let am = self
                    .histograms
                    .entry(key)
                    .or_insert_with(|| AggregatedMetric {
                        value: Histogram::new(3).unwrap(),
                        tags: Tags::new(),
                    });
                am.value.saturating_record(value.get());
                am.tags.append(&mut tags);
            }
            _ => unreachable!(),
        }
    }

    pub fn counter(&self, key: &str) -> Option<&AggregatedMetric<f64>> {
        self.counters.get(key)
    }

    pub fn gauge(&self, key: &str) -> Option<&AggregatedMetric<f64>> {
        self.gauges.get(key)
    }

    pub fn uniques(&self, key: &str) -> Option<usize> {
        self.sets.get(key).map(|am| am.value.len())
    }

    pub fn flush(&mut self) -> Vec<Measurement> {
        let mut metrics = Vec::new();
        metrics.extend(self.counters.drain().map(|(name, v)| {
            Measurement::new(kind::COUNTER, name, Unit::Count(v.value as u64), v.tags)
        }));
        metrics.extend(self.gauges.drain().map(|(name, v)| {
            Measurement::new(kind::GAUGE, name, Unit::Count(v.value as u64), v.tags)
        }));
        for (name, mut v) in self.timers.drain() {
            let tags = v.tags;
            metrics.extend(v.value.drain(..).map(|t| {
                Measurement::new(
                    kind::TIMER,
                    name.clone(),
                    Unit::Count(t as u64),
                    tags.clone(),
                )
            }));
        }
        metrics.extend(self.sets.drain().map(|(name, v)| {
            Measurement::new(
                kind::SET_UNIQUES,
                name,
                Unit::Count(v.value.len() as u64),
                v.tags,
            )
        }));
        for (name, v) in self.histograms.drain() {
            metrics.extend(PERCENTILES.iter().cloned().map(|p| {
                Measurement::new(
                    kind::PERCENTILE,
                    name.clone(),
                    Unit::Percentile(p as u64, v.value.value_at_percentile(p)),
                    v.tags.clone(),
                )
            }));
        }

        metrics
    }
}

pub struct AggregatorActor {
    aggregator: Aggregator,
    config: AggregatorConfig,
    upstream: Recipient<Message>,
}

impl AggregatorActor {
    pub fn launch(config: AggregatorConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let actor = AggregatorActor {
            aggregator: Aggregator::new(),
            config,
            upstream,
        };
        actor.start().recipient()
    }

    fn flush(&mut self, _ctx: &mut Context<Self>) {
        info!("flushing");
        let metrics = self.aggregator.flush();
        if !metrics.is_empty() {
            let message = Message::List(metrics);
            self.upstream.do_send(message.clone()).unwrap();
        }
    }
}

impl Actor for AggregatorActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        IntervalFunc::new(
            Duration::from_millis(self.config.flush_interval),
            Self::flush,
        )
        .finish()
        .spawn(ctx);
    }
}

impl Handler<Message> for AggregatorActor {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(mut ms) => {
                for m in ms.drain(..) {
                    self.aggregator.record(m);
                }
            }
            Message::Single(m) => self.aggregator.record(m),
        }
    }
}

fn default_flush_interval() -> u64 {
    10000
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AggregatorConfig {
    #[serde(default = "default_flush_interval")]
    pub flush_interval: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grains::statsd::{parse_metric, Metric};

    fn metric(s: &str) -> Metric {
        parse_metric(s).unwrap()
    }

    #[test]
    fn test_aggregate_counter() {
        let mut a = Aggregator::new();
        assert_eq!(a.counter("foo"), None);
        a.record(metric("foo:1|c"));
        assert_eq!(a.counter("foo").unwrap().value, 1f64);
        a.record(metric("foo:2|c"));
        assert_eq!(a.counter("foo").unwrap().value, 3f64);
    }

    #[test]
    fn test_aggregate_gauge() {
        let mut a = Aggregator::new();
        assert_eq!(a.gauge("foo"), None);
        a.record(metric("foo:1|g"));
        assert_eq!(a.gauge("foo").unwrap().value, 1f64);
        a.record(metric("foo:2|g"));
        assert_eq!(a.gauge("foo").unwrap().value, 2f64);
        a.record(metric("foo:+3|g"));
        assert_eq!(a.gauge("foo").unwrap().value, 5f64);
        /*
        FIXME: re-enable after switching everything to f64
        a.record(metric("foo:-5|g"));
        assert_eq!(a.gauge("foo").unwrap().value, -1f64);
        */
    }

    #[test]
    fn test_aggregate_set() {
        let mut a = Aggregator::new();
        assert_eq!(a.uniques("foo"), None);
        a.record(metric("foo:bar|s"));
        assert_eq!(a.uniques("foo"), Some(1));
        a.record(metric("foo:bar|s"));
        assert_eq!(a.uniques("foo"), Some(1));
        a.record(metric("foo:bad|s"));
        assert_eq!(a.uniques("foo"), Some(2));
        a.record(metric("bar:baz|s"));
        assert_eq!(a.uniques("bar"), Some(1));
    }
}
