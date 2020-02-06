use actix::prelude::*;
use rayon::prelude::*;

use crate::backends::Message;
use crate::metrics::Measurement;

pub struct AddSystemDetails {
    host: String,
    kernel: String,
    upstream: Recipient<Message>,
}

impl Actor for AddSystemDetails {
    type Context = Context<Self>;
}

impl AddSystemDetails {
    pub fn launch(upstream: Recipient<Message>) -> Recipient<Message> {
        use redbpf::uname::*;

        let uts = uname().unwrap();
        let kernel = to_str(&uts.release).to_string();

        AddSystemDetails {
            host: get_fqdn().unwrap(),
            kernel,
            upstream,
        }
        .start()
        .recipient()
    }
}

fn add_tags(msg: &mut Measurement, host: String, kernel: String) {
    msg.tags.insert("host".to_string(), host);
    msg.tags.insert("kernel".to_string(), kernel);
}

impl Handler<Message> for AddSystemDetails {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let host = self.host.clone();
        let kernel = self.kernel.clone();
        match msg {
            Message::List(ref mut ms) => ms
                .par_iter_mut()
                .for_each(move |m| add_tags(m, host.clone(), kernel.clone())),
            Message::Single(ref mut m) => add_tags(m, host, kernel),
        }

        self.upstream.do_send(msg).unwrap();
    }
}
