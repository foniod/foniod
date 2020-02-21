use ::actix::prelude::*;
use crate::backends::Message;
use crate::backends::encoders::to_json;

#[derive(Default)]
pub struct Console;

impl Actor for Console {
    type Context = Context<Self>;
}

impl Handler<Message> for Console {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let mut measurements = match msg {
            Message::Single(m) => vec![m],
            Message::List(ms) => ms,
        };

	for m in measurements.drain(..) {
            println!("{}", String::from_utf8(to_json(&[m])).unwrap());
	}
    }
}
