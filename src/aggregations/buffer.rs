use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use actix::utils::IntervalFunc;
use actix::{Actor, ActorStream, Context, ContextFutureSpawner, Handler, Recipient};
use hdrhistogram::Histogram;

use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit, UnitType};

const PERCENTILES: [f64; 6] = [25f64, 50f64, 75f64, 90f64, 95f64, 99f64];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MeasurementKey {
    name: String,
    tags_hash: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct AggregatedMetric<T: PartialEq> {
    value: T,
    unit: UnitType,
    tags: Tags,
}

#[derive(Debug)]
struct Aggregator {
    counters: HashMap<MeasurementKey, AggregatedMetric<f64>>,
    gauges: HashMap<MeasurementKey, AggregatedMetric<f64>>,
    timers: HashMap<MeasurementKey, AggregatedMetric<Vec<f64>>>,
    sets: HashMap<MeasurementKey, AggregatedMetric<HashSet<String>>>,
    histograms: HashMap<MeasurementKey, AggregatedMetric<Histogram<u64>>>,

    enable_histograms: bool,
}

impl Aggregator {
    pub fn new(enable_histograms: bool) -> Self {
        Aggregator {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            timers: HashMap::new(),
            sets: HashMap::new(),
            histograms: HashMap::new(),

            enable_histograms,
        }
    }

    pub fn max_len(&self) -> usize {
        *[self.counters.len(), self.gauges.len(), self.timers.len(), self.sets.len(), self.histograms.len()].iter().max().unwrap()
    }

    pub fn record<T: Into<Measurement>>(&mut self, measurement: T) {
        use kind::*;

        let measurement = measurement.into();
        let key = measurement_key(&measurement);
        let Measurement {
            kind,
            value,
            sample_rate,
            reset,
            tags,
            ..
        } = measurement;

        let v = match kind {
            x if (x & kind::COUNTER > 0) | (x & kind::GAUGE > 0) | (x & kind::TIMER > 0) => {
                value.get() as f64
            }
            _ => 0f64,
        };

        if kind & kind::COUNTER != 0 {
            let am = self
                .counters
                .entry(key.clone())
                .or_insert_with(|| AggregatedMetric {
                    unit: value.get_type(),
                    value: 0f64,
                    tags: tags.clone(),
                });
            am.value += v / sample_rate.unwrap_or(1.0);
        }
        if kind & kind::GAUGE != 0 {
            let am = self
                .gauges
                .entry(key.clone())
                .or_insert_with(|| AggregatedMetric {
                    unit: value.get_type(),
                    value: 0f64,
                    tags: tags.clone(),
                });
            if reset {
                am.value = v;
            } else {
                am.value += v;
            }
        }
        if kind & kind::TIMER != 0 {
            let am = self
                .timers
                .entry(key.clone())
                .or_insert_with(|| AggregatedMetric {
                    unit: value.get_type(),
                    value: Vec::new(),
                    tags: tags.clone(),
                });
            am.value.push(v);
        }
        if kind & kind::SET != 0 {
            let am = self
                .sets
                .entry(key.clone())
                .or_insert_with(|| AggregatedMetric {
                    unit: value.get_type(),
                    value: HashSet::new(),
                    tags: tags.clone(),
                });
            if let Unit::Str(v) = &value {
                am.value.insert(v.to_string());
            }
        }
        if self.enable_histograms && kind & kind::HISTOGRAM != 0 {
            let am = self
                .histograms
                .entry(key)
                .or_insert_with(|| AggregatedMetric {
                    unit: value.get_type(),
                    value: Histogram::new(3).unwrap(),
                    tags,
                });
            am.value.saturating_record(value.get());
        }
    }

    pub fn counter(&self, key: &MeasurementKey) -> Option<&AggregatedMetric<f64>> {
        self.counters.get(key)
    }

    pub fn gauge(&self, key: &MeasurementKey) -> Option<&AggregatedMetric<f64>> {
        self.gauges.get(key)
    }

    pub fn uniques(&self, key: &MeasurementKey) -> Option<usize> {
        self.sets.get(key).map(|am| am.value.len())
    }

    pub fn flush(&mut self) -> Vec<Measurement> {
        let mut metrics = Vec::new();
        metrics.extend(self.counters.drain().map(|(k, v)| {
            Measurement::new(
                kind::COUNTER,
                k.name,
                v.unit.to_unit(v.value as u64),
                v.tags,
            )
        }));
        self.counters.shrink_to_fit();
        
        metrics.extend(self.gauges.drain().map(|(k, v)| {
            Measurement::new(kind::GAUGE, k.name, v.unit.to_unit(v.value as u64), v.tags)
        }));
        self.gauges.shrink_to_fit();
        
        for (k, mut v) in self.timers.drain() {
            let tags = v.tags;
            metrics.extend(v.value.drain(..).map(|t| {
                Measurement::new(
                    kind::TIMER,
                    k.name.clone(),
                    Unit::Count(t as u64),
                    tags.clone(),
                )
            }));
        }
        self.timers.shrink_to_fit();
        
        for (k, v) in self.sets.drain() {
            let mut tags = v.tags;
            if let Some(elements) = join(v.value.iter(), ",") {
                tags.insert("set_elements", elements);
            }
            metrics.push(Measurement::new(
                kind::SET,
                k.name,
                Unit::Count(v.value.len() as u64),
                tags,
            ));
        }
        self.sets.shrink_to_fit();
        
        for (k, v) in self.histograms.drain() {
            metrics.extend(PERCENTILES.iter().cloned().map(|p| {
                Measurement::new(
                    kind::PERCENTILE,
                    format!("{}_{}", k.name, p),
                    Unit::Count(v.value.value_at_percentile(p)),
                    v.tags.clone(),
                )
            }));
        }
        self.histograms.shrink_to_fit();

        metrics
    }
}

fn hash_tags(tags: &Tags) -> u64 {
    let mut hasher = DefaultHasher::default();
    tags.hash(&mut hasher);
    hasher.finish()
}

fn measurement_key(metric: &Measurement) -> MeasurementKey {
    MeasurementKey {
        name: metric.name.clone(),
        tags_hash: hash_tags(&metric.tags),
    }
}

pub struct Buffer {
    aggregator: Aggregator,
    config: BufferConfig,
    upstream: Recipient<Message>,
}

impl Buffer {
    pub fn launch(config: BufferConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Actor::start_in_arbiter(&actix::Arbiter::new(), |_| Buffer {
            aggregator: Aggregator::new(config.enable_histograms),
            config,
            upstream,
        })
        .recipient()
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

impl Actor for Buffer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let ms = self
            .config
            .interval_s
            .map(|s| s * 1000)
            .unwrap_or(self.config.interval_ms);
        IntervalFunc::new(Duration::from_millis(ms), Self::flush)
            .finish()
            .spawn(ctx);
    }
}

impl Handler<Message> for Buffer {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        if let Some(max_elems) = self.config.max_records {
            if self.aggregator.max_len() > max_elems as usize {
                self.aggregator.flush();
            }
        }

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

fn default_interval_ms() -> u64 {
    10000
}

fn default_enable_histograms() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BufferConfig {
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    pub interval_s: Option<u64>,
    pub max_records: Option<u64>,
    #[serde(default = "default_enable_histograms")]
    pub enable_histograms: bool,
}

fn join<T: Into<String>, I: Iterator<Item = T>>(mut iter: I, sep: &str) -> Option<String> {
    if let Some(item) = iter.next() {
        let mut ret = item.into();
        for item in iter {
            ret.push_str(sep);
            ret.push_str(&item.into());
        }
        return Some(ret);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grains::statsd::{parse_metric, Metric};

    fn key(name: &str) -> MeasurementKey {
        let tags = Tags::new();
        MeasurementKey {
            name: name.to_string(),
            tags_hash: hash_tags(&tags),
        }
    }

    fn metric(s: &str) -> Metric {
        parse_metric(s).unwrap()
    }

    #[test]
    fn test_aggregate_counter() {
        let mut a = Aggregator::new(false);
        let k = key("foo");
        assert_eq!(a.counter(&k), None);
        a.record(metric("foo:1|c"));
        assert_eq!(a.counter(&k).unwrap().value, 1f64);
        a.record(metric("foo:2|c"));
        assert_eq!(a.counter(&k).unwrap().value, 3f64);
    }

    #[test]
    fn test_aggregate_gauge() {
        let mut a = Aggregator::new(false);
        let foo = key("foo");
        assert_eq!(a.gauge(&foo), None);
        a.record(metric("foo:1|g"));
        assert_eq!(a.gauge(&foo).unwrap().value, 1f64);
        a.record(metric("foo:2|g"));
        assert_eq!(a.gauge(&foo).unwrap().value, 2f64);
        a.record(metric("foo:+3|g"));
        assert_eq!(a.gauge(&foo).unwrap().value, 5f64);
        /*
        FIXME: re-enable after switching everything to f64
        a.record(metric("foo:-5|g"));
        assert_eq!(a.gauge("foo").unwrap().value, -1f64);
        */
    }

    #[test]
    fn test_aggregate_set() {
        let mut a = Aggregator::new(false);
        let foo = key("foo");
        let bar = key("bar");
        assert_eq!(a.uniques(&foo), None);
        a.record(metric("foo:bar|s"));
        assert_eq!(a.uniques(&foo), Some(1));
        a.record(metric("foo:bar|s"));
        assert_eq!(a.uniques(&foo), Some(1));
        a.record(metric("foo:bad|s"));
        assert_eq!(a.uniques(&foo), Some(2));
        a.record(metric("bar:baz|s"));
        assert_eq!(a.uniques(&bar), Some(1));
    }
}
