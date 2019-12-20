use std::collections::HashMap;

use actix::prelude::*;
use futures::{finished, Future};
use hyper::{client::HttpConnector, header, Body, Client, HeaderMap, Method, Request, Uri};
use hyper_rustls::HttpsConnector;

use crate::backends::encoders::Encoding;
use crate::backends::Message;

pub struct HTTP {
    headers: HeaderMap,
    uri: Uri,
    client: Client<HttpsConnector<HttpConnector>>,
    encoding: Encoding,
    content_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HTTPConfig {
    uri: String,
    headers: HashMap<String, String>,
    threads: Option<usize>,
    encoding: Option<Encoding>,
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
                headers.insert(
                    header::HeaderName::from_bytes(h.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }

            headers
        };

        let encoding = config.encoding.unwrap_or(Encoding::JSON);
        let content_type = match &encoding {
            Encoding::JSON => "application/json",
            #[cfg(feature = "capnp-encoding")]
            Encoding::Capnp => "application/octet-stream",
        }
        .to_string();

        HTTP {
            headers,
            client,
            uri,
            encoding,
            content_type,
        }
    }
}

impl Actor for HTTP {
    type Context = Context<Self>;
}

impl Handler<Message> for HTTP {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let measurements = match msg {
            Message::Single(m) => vec![m],
            Message::List(ms) => ms,
        };

        let mut req = Request::new(Body::from(self.encoding.encode(&measurements)));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = self.uri.clone();
        req.headers_mut().clone_from(&self.headers);
        req.headers_mut()
            .insert(header::CONTENT_TYPE, self.content_type.parse().unwrap());

        ::actix::spawn(
            self.client
                .request(req)
                .and_then(|_| finished(()))
                .or_else(|_| finished(())),
        );
    }
}
