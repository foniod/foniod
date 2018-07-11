use actix::prelude::*;
use futures::Future;
pub use rusoto_core::region::Region;
use rusoto_s3::{PutObjectRequest, S3 as RusotoS3, S3Client};
use serde_json;

use backends::Message;
use metrics::timestamp_now;

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
            client: S3Client::simple(region),
            bucket: bucket.into(),
        }
    }
}

impl Actor for S3 {
    type Context = Context<Self>;
}

impl Handler<Message> for S3 {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        ::actix::spawn(
            self.client
                .put_object(&PutObjectRequest {
                    bucket: self.bucket.clone(),
                    key: format!("{}_{}", &self.hostname, timestamp_now()),
                    body: Some(serde_json::to_string(&msg).unwrap().into()),
                    ..Default::default()
                })
                .and_then(|_| Ok(()))
                .or_else(|_| Ok(())),
        );
    }
}
