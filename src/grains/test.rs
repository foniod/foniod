use actix::{Actor, AsyncContext, Context, Recipient, StreamHandler};
use futures::{Async, Poll, Stream};

use crate::backends::Message;
use crate::metrics::{kind, timestamp_now, Measurement, Tags, Unit};

pub struct TestProbe {
    config: TestProbeConfig,
    recipients: Vec<Recipient<Message>>,
}

impl TestProbe {
    pub fn with_config(config: TestProbeConfig, recipients: Vec<Recipient<Message>>) -> Self {
        TestProbe { config, recipients }
    }
}

impl Actor for TestProbe {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("debug probe started");
        let unit = Unit::try_from_str(
            &self.config.measurement_type,
            self.config.measurement.parse().unwrap_or_default(),
        )
        .unwrap();
        let kind = kind::try_from_str(&self.config.aggregation_type.as_ref().unwrap()).unwrap();
        ctx.add_stream(MeasurementStream::new(
            self.config.name.clone(),
            unit,
            kind,
            self.config.tags.clone(),
        ));
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("debug daemon stopped");
    }
}

impl StreamHandler<Message, ()> for TestProbe {
    fn handle(&mut self, message: Message, _ctx: &mut Context<TestProbe>) {
        for recipient in &self.recipients {
            recipient.do_send(message.clone()).unwrap();
        }
    }
}

pub struct MeasurementStream {
    name: String,
    unit: Unit,
    kind: kind::Kind,
    tags: Vec<Tag>,
}

impl MeasurementStream {
    fn new(name: String, unit: Unit, kind: kind::Kind, tags: Vec<Tag>) -> Self {
        MeasurementStream {
            name,
            unit,
            kind,
            tags,
        }
    }
}

impl Stream for MeasurementStream {
    type Item = Message;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut tags = Tags::new();
        for (key, value) in &self.tags {
            let value = match value.as_str() {
                "$TS" => format!("{}", timestamp_now()),
                _ => value.clone(),
            };
            tags.insert(key.clone(), value);
        }
        let measurement = Measurement::new(
            self.kind,
            self.name.clone(),
            self.unit.clone(),
            tags,
        );
        let message = Message::Single(measurement);
        Ok(Async::Ready(Some(message)))
    }
}

pub type Tag = (String, String);

#[derive(Serialize, Deserialize, Debug)]
pub struct TestProbeConfig {
    name: String,
    measurement: String,
    measurement_type: String,
    aggregation_type: Option<String>,
    tags: Vec<Tag>,
}
