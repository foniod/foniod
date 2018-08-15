use std::collections::HashMap;

use actix::prelude::*;
use futures::Future;
pub use rusoto_core::region::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3 as RusotoS3};
use serde_json;

use serde::Serialize;

use backends::Message;
use metrics::{kind::Kind, timestamp_now, Measurement, Unit};

pub struct S3 {
    hostname: String,
    client: S3Client,
    bucket: String,
}

impl S3 {
    pub fn new(region: Region, bucket: impl Into<String>) -> S3 {
        use redbpf::uname::*;

        S3 {
            hostname: get_fqdn().unwrap(),
            client: S3Client::new(region),
            bucket: bucket.into(),
        }
    }
}

impl Actor for S3 {
    type Context = Context<Self>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SerializedMeasurement {
    timestamp: u64,
    pub kind: Kind,
    pub name: String,
    pub measurement: u64,
    pub tags: HashMap<String, String>,
}

fn format_by_type(mut msg: Measurement) -> impl Serialize {
    let (type_str, measurement) = match msg.value {
        Unit::Byte(x) => ("byte", x),
        Unit::Count(x) => ("count", x),
    };

    let name = format!("{}_{}", &msg.name, type_str);

    SerializedMeasurement {
        timestamp: msg.timestamp,
        kind: msg.kind,
        name,
        measurement,
        tags: msg.tags.drain(..).collect(),
    }
}

impl Handler<Message> for S3 {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let body = match msg {
            Message::List(ref mut lst) => format!(
                "[{}]",
                lst.drain(..)
                    .map(|e| serde_json::to_string(&format_by_type(e)).unwrap())
                    .collect::<Vec<String>>()
                    .join(",\n")
            ),
            Message::Single(msg) => serde_json::to_string(&[format_by_type(msg)]).unwrap(),
        }.into_bytes().into();

        ::actix::spawn(
            self.client
                .put_object(PutObjectRequest {
                    bucket: self.bucket.clone(),
                    key: format!("{}_{}", &self.hostname, timestamp_now()),
                    body: Some(body),
                    ..Default::default()
                }).and_then(|_| Ok(()))
                .or_else(|_| Ok(())),
        );
    }
}
