use actix::prelude::*;
use backends::Message;

#[derive(Default)]
pub struct Console;

impl Actor for Console {
    type Context = Context<Self>;
}

impl Handler<Message> for Console {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        println!("{:?}", msg);
    }
}
