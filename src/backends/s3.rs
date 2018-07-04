use std::sync::Mutex;

use actix::prelude::*;
pub use rusoto_core::region::Region;
use rusoto_s3::{PutObjectRequest, S3 as RusotoS3, S3Client};
use serde_json;

use backends::Flush;
use metrics::{nano_timestamp_now, Measurement};

pub struct S3 {
    client: S3Client,
    bucket: String,
    events: Mutex<Vec<Measurement>>,
}

impl S3 {
    pub fn new(region: Region, bucket: impl Into<String>) -> S3 {
        S3 {
            client: S3Client::simple(region),
            bucket: bucket.into(),
            events: Mutex::new(vec![]),
        }
    }
}

impl Actor for S3 {
    type Context = Context<Self>;
}

impl Handler<Measurement> for S3 {
    type Result = ();

    fn handle(&mut self, msg: Measurement, _ctx: &mut Context<Self>) -> Self::Result {
        self.events.lock().unwrap().push(msg);
    }
}

impl Handler<Flush> for S3 {
    type Result = ();

    fn handle(&mut self, _: Flush, _ctx: &mut Context<Self>) -> Self::Result {
        let message = {
            let mut evs = self.events.lock().unwrap();
            if evs.len() == 0 {
                return;
            }

            let json = serde_json::to_string(&*evs).unwrap();
            evs.clear();

            json
        };

        self.client
            .put_object(&PutObjectRequest {
                bucket: self.bucket.clone(),
                key: nano_timestamp_now().to_string(),
                body: Some(message.into()),
                ..Default::default()
            })
            .sync().unwrap();
    }
}
