use actix::Recipient;

pub mod console;
pub mod s3;
pub mod statsd;

use metrics::Measurement;

pub type BackendHandler = Recipient<Message>;

#[derive(Debug, Message, Serialize)]
#[serde(untagged)]
pub enum Message {
    Single(Measurement),
    List(Vec<Measurement>),
}

#[derive(Message)]
pub struct Flush;

impl ::actix::Message for Measurement {
    type Result = ();
}
