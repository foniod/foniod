use std::collections::HashMap;

use actix::prelude::*;
use futures::{finished, Future};
use hyper::{client::HttpConnector, header, Body, Client, HeaderMap, Method, Request, Uri};
use hyper_rustls::HttpsConnector;
use rayon::prelude::*;

use crate::backends::encoders::Encoding;
use crate::backends::Message;

pub struct HTTP {
    headers: HeaderMap,
    uri: Uri,
    client: Client<HttpsConnector<HttpConnector>>,
    encoding: Encoding,
    content_type: String,
    parallel_chunk_size: usize
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HTTPConfig {
    uri: String,
    headers: HashMap<String, String>,
    threads: Option<usize>,
    encoding: Option<Encoding>,
    parallel_chunk_size: Option<usize>,
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

        let parallel_chunk_size = config.parallel_chunk_size.unwrap_or(0);

        HTTP {
            headers,
            client,
            uri,
            encoding,
            content_type,
            parallel_chunk_size
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

        let encoding = self.encoding;
        let payloads: Vec<_> = if self.parallel_chunk_size > 0 {
            measurements
                .into_par_iter()
                .chunks(self.parallel_chunk_size)
                .map(|chunks| encoding.encode(&chunks))
                .collect()
        } else {
            vec![encoding.encode(&measurements)]
        };

        for payload in payloads {
            let mut req = Request::new(Body::from(payload));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = self.uri.clone();
            req.headers_mut().clone_from(&self.headers);
            req.headers_mut()
                .insert(header::CONTENT_TYPE, self.content_type.parse().unwrap());

            actix::spawn(
                self.client
                    .request(req)
                    .and_then(|_| finished(()))
                    .or_else(|_| finished(())),
            );
        }
    }
}
