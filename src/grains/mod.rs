mod connection;
pub mod tcpv4;
pub mod udp;

pub use backends::Backend;
pub use metrics::Measurement;
pub use redbpf::{LoadError, PerfMap, Result};
pub use std::collections::HashMap;
use std::marker::PhantomData;

use redbpf::{Map, Module};

pub struct Grain<T> {
    module: Module,
    _type: PhantomData<T>,
}

pub struct ActiveGrain<T> {
    grain: Grain<T>,
    perfmaps: Vec<PerfMap>,
}

impl<'code, 'module, T> Grain<T>
where
    T: EBPFModule<'code>,
{
    pub fn load() -> Result<Self> {
        let mut module = Module::parse(T::code())?;
        for prog in module.programs.iter_mut() {
            prog.load(module.version, module.license.clone()).unwrap();
            println!(
                "prog loaded: {} {} {:?}",
                prog.attach().is_ok(),
                prog.name,
                prog.kind
            );
        }

        Ok(Grain {
            module,
            _type: PhantomData,
        })
    }

    pub fn bind(mut self, client: &'module Backend) -> ActiveGrain<T> {
        let perfmaps = self
            .module
            .maps
            .drain(..)
            .map(|m| T::handler(m, client))
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .collect();

        ActiveGrain {
            grain: self,
            perfmaps,
        }
    }
}

impl<T> ActiveGrain<T> {
    pub fn poll(&mut self) {
        for pm in self.perfmaps.iter_mut() {
            pm.poll(10);
        }
    }
}

pub trait EBPFModule<'code> {
    fn code() -> &'code [u8];
    fn handler(map: Map, upstream: &Backend) -> Result<PerfMap>;
}
