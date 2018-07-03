mod connection;
pub mod tcpv4;
// pub mod udp;
use actix::Recipient;
use metrics::Measurement;
use redbpf::{Map, Module, PerfMap, Result};

pub trait EBPFModule<'c, 'm> {
    fn load() -> Result<Module> {
        let mut module = Module::parse(Self::code())?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
            println!(
                "prog loaded: {} {} {:?}",
                prog.attach().is_ok(),
                prog.name,
                prog.kind
            );
        }

        Ok(module)
    }

    fn bind(module: &'m mut Module, client: &Recipient<Measurement>) -> Vec<PerfMap<'m>> {
        module
            .maps
            .iter_mut()
            .map(|m| Self::handler(m, client))
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .collect()
    }

    fn code() -> &'c [u8];
    fn handler(map: &'m mut Map, client: &Recipient<Measurement>) -> Result<PerfMap<'m>>;
}
