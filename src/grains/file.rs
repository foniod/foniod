#![allow(non_camel_case_types)]

use std::ptr;
use std::sync::Mutex;
use std::time::{Instant,Duration};

use grains::*;

include!(concat!(env!("OUT_DIR"), "/file.rs"));

pub struct Files;

impl EBPFGrain<'static> for Files {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/file.elf"))
    }

    fn get_handler(id: &str) -> EventCallback {
        let hm = Mutex::new(vec![]);
        let ts = Mutex::new(Instant::now());

        Box::new(move |raw| {
            println!("{:?}", FileAccess::from(_data_file::from(raw)));

            let mut evs = hm.lock().unwrap();
            evs.push(1);

            let mut last = ts.lock().unwrap();
            let now = Instant::now();
            if now - *last > Duration::from_secs(1) {
                println!("{}", evs.len());
                *last = now;
                evs.clear();
            }

            None
        })
    }
}

#[derive(Debug)]
pub struct FileAccess {
    pub process: String,
    pub name: String,
}

impl From<_data_file> for FileAccess {
    fn from(data: _data_file) -> FileAccess {
        FileAccess {
            process: to_string(unsafe { &*(&data.comm as *const [i8] as *const [u8]) }),
            name: to_string(unsafe { &*(&data.path[0].name as *const [i8] as *const [u8]) }),
        }
    }
}
