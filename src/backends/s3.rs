use std::env;

use actix::prelude::*;
use futures::Future;
pub use rusoto_core::region::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3 as RusotoS3};

use backends::Message;
use metrics::timestamp_now;

pub struct S3 {
    hostname: String,
    client: S3Client,
    bucket: String,
}

impl S3 {
    pub fn new() -> S3 {
        use redbpf::uname::*;

        let bucket = env::var("AWS_S3_BUCKET")
            .expect("The AWS_S3_BUCKET environment variable has to be specified!");

        S3 {
            hostname: get_fqdn().unwrap(),
            client: S3Client::new(Region::default()),
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
        let body = msg.to_string().into_bytes().into();

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
