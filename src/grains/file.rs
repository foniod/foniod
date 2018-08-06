#![allow(non_camel_case_types)]

use std::collections::HashMap;
use std::ptr;
use std::rc::Rc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use std::fs::metadata;
use std::os::unix::fs::MetadataExt;

use redbpf::{Map, Module, VoidPtr};

use grains::*;

include!(concat!(env!("OUT_DIR"), "/file.rs"));

const ACTION_IGNORE: u8 = 0;
const ACTION_RECORD: u8 = 1;

fn find_map_by_name<'a>(module: &'a mut Module, needle: &str) -> (usize, &'a mut Map) {
    module
        .maps
        .iter_mut()
        .enumerate()
        .find(|(i, v)| v.name == needle)
        .unwrap()
}

pub struct Files {
    files: Mutex<HashMap<u32, String>>,
    actionlist: HashMap<String, String>,
    backends: Vec<BackendHandler>,
    volumes: Option<Map>,
}

impl Files {
    pub fn new() -> Files {
        Files {
            files: Mutex::new(HashMap::new()),
            actionlist: HashMap::new(),
            backends: vec![],
            volumes: None,
        }
    }
}

impl EBPFGrain<'static> for Files {
    fn loaded(&mut self, module: &mut Module) {
        let (volidx, _) = find_map_by_name(module, "volumes");

        {
            let (_, actionlist) = find_map_by_name(module, "actionlist");

            let mut record = _data_action {
                action: ACTION_RECORD,
            };
            let mut ino = metadata("/").unwrap().ino();
            actionlist.set(
                &mut ino as *mut u64 as VoidPtr,
                &mut record as *mut _data_action as VoidPtr,
            );
        }

        let mut volumes = module.maps.swap_remove(volidx);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));

            for mut k in volumes.iter::<u32>() {
                println!("connection: {:?}", k);

                let ptr = Rc::get_mut(&mut k).unwrap() as *mut u32 as VoidPtr;
                volumes.delete(ptr);
            }
        });
    }

    fn attached(&mut self, backends: &[BackendHandler]) {
        self.backends.extend_from_slice(backends);
    }

    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/file.elf"))
    }

    fn get_handler(&self, id: &str) -> EventCallback {
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
