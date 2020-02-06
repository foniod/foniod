#![deny(clippy::all)]

#[macro_use]
extern crate actix;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
pub mod aggregations;
pub mod backends;
pub mod config;
pub mod grains;
pub mod metrics;
#[cfg(feature = "capnp-encoding")]
mod ingraind_capnp {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/schema/ingraind_capnp.rs"));
}