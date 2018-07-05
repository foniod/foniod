use actix::prelude::*;
use metrics::Measurement;

#[derive(Default)]
pub struct Console;

impl Actor for Console {
    type Context = Context<Self>;
}

impl Handler<Measurement> for Console {
    type Result = ();

    fn handle(&mut self, msg: Measurement, _ctx: &mut Context<Self>) -> Self::Result {
        println!("{:?}", msg);
    }
}
