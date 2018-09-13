use actix::prelude::*;
use futures::{finished, Future};
use hyper::{client::HttpConnector, header, Body, Client, Method, Request, Uri};
use hyper_rustls::HttpsConnector;

use backends::Message;

#[derive(Serialize, Deserialize, Debug)]
pub struct HTTPConfig {
    uri: String,
    authorization: String,
    threads: Option<usize>,
}

pub struct HTTP {
    authorization: String,
    uri: Uri,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl HTTP {
    pub fn new(config: HTTPConfig) -> HTTP {
        let client = Client::builder()
            .keep_alive(true)
            .build(HttpsConnector::new(config.threads.unwrap_or(4)));
        let uri = config.uri.parse().unwrap();

        HTTP {
            authorization: config.authorization,
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
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application.json()".parse().unwrap());
        req.headers_mut()
            .insert(header::AUTHORIZATION, self.authorization.parse().unwrap());

        ::actix::spawn(
            self.client
                .request(req)
                .and_then(|_| finished(()))
                .or_else(|_| finished(())),
        );
    }
}
