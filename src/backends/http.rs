use std::collections::HashMap;

use ::actix::prelude::*;
use futures::{finished, Future};
use hyper::{client::HttpConnector, header, Body, Client, Method, Request, Uri, HeaderMap};
use hyper_rustls::HttpsConnector;

use crate::backends::Message;

#[derive(Serialize, Deserialize, Debug)]
pub struct HTTPConfig {
    uri: String,
    headers: HashMap<String, String>,
    threads: Option<usize>,
}

pub struct HTTP {
    headers: HeaderMap,
    uri: Uri,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl HTTP {
    pub fn new(config: HTTPConfig) -> HTTP {
        let client = Client::builder()
            .keep_alive(false)
            .build(HttpsConnector::new(config.threads.unwrap_or(4)));
        let uri = config.uri.parse().unwrap();

        let headers = {
            let mut headers = HeaderMap::new();
            for (h, v) in config.headers.iter() {
                headers.insert(header::HeaderName::from_bytes(h.as_bytes()).unwrap(), v.parse().unwrap());
            }

            headers
        };

        HTTP {
            headers,
            client,
            uri,
        }
    }
}

impl Actor for HTTP {
    type Context = Context<Self>;
}

impl Handler<Message> for HTTP {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let mut req = Request::new(Body::from(msg.to_string()));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = self.uri.clone();
        req.headers_mut().clone_from(&self.headers);
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        ::actix::spawn(
            self.client
                .request(req)
                .and_then(|_| finished(()))
                .or_else(|_| finished(())),
        );
    }
}
