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

#[derive(Debug, Clone)]
pub enum Message {
    Single(Measurement),
    List(Vec<Measurement>),
}

impl actix::Message for Message {
    type Result = ();
}
