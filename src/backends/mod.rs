use actix;

pub mod console;
#[cfg(feature = "http-backend")]
pub mod http;
#[cfg(feature = "s3-backend")]
pub mod s3;
#[cfg(feature = "statsd-backend")]
pub mod statsd;

mod encoders;

use crate::metrics::{kind::Kind, Measurement, Unit};

pub type BackendHandler = actix::Recipient<Message>;

#[derive(Message)]
pub struct Flush;

impl actix::Message for Measurement {
    type Result = ();
}

#[derive(Debug, Clone, Message)]
pub enum Message {
    Single(Measurement),
    List(Vec<Measurement>),
}
