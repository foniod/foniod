use std::sync::Mutex;

use actix::prelude::*;
use futures::Future;
pub use rusoto_core::region::Region;
use rusoto_s3::{PutObjectRequest, S3 as RusotoS3, S3Client};
use serde_json;

use backends::Flush;
use metrics::{timestamp_now, Measurement};

pub struct S3 {
    kernel: String,
    hostname: String,
    client: S3Client,
    bucket: String,
    events: Mutex<String>,
}

impl S3 {
    pub fn new(region: Region, bucket: impl Into<String>) -> S3 {
        use redbpf::uname::*;

        let uts = uname().unwrap();
        let hostname = get_fqdn().unwrap();

        S3 {
            kernel: to_str(&uts.release).to_string(),
            hostname,
            client: S3Client::simple(region),
            bucket: bucket.into(),
            events: Mutex::new(String::new()),
        }
    }
}

impl Actor for S3 {
    type Context = Context<Self>;
}

impl Handler<Measurement> for S3 {
    type Result = ();

    fn handle(&mut self, mut msg: Measurement, _ctx: &mut Context<Self>) -> Self::Result {
        msg.tags.insert("host".to_string(), self.hostname.clone());
        msg.tags.insert("kernel".to_string(), self.kernel.clone());

        let mut buffer = self.events.lock().unwrap();

        buffer.push_str(&serde_json::to_string(&msg).unwrap());
        buffer.push(',');
        buffer.push('\n');
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

            let json = evs.clone();
            evs.clear();

            format!("[{}]", json)
        };

        ::actix::spawn(
            self.client
                .put_object(&PutObjectRequest {
                    bucket: self.bucket.clone(),
                    key: format!("{}_{}", &self.hostname, timestamp_now()),
                    body: Some(message.into()),
                    ..Default::default()
                })
                .and_then(|_| Ok(()))
                .or_else(|_| Ok(())),
        );
    }
}
