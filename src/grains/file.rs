#![allow(non_camel_case_types)]

use std::ptr;

use std::fs::metadata;
use std::os::unix::fs::MetadataExt;

use redbpf::{Map, Module, VoidPtr};

use grains::*;

include!(concat!(env!("OUT_DIR"), "/file.rs"));

type ino_t = u64;

const ACTION_IGNORE: u8 = 0;
const ACTION_RECORD: u8 = 1;

fn find_map_by_name<'a>(module: &'a Module, needle: &str) -> &'a Map {
    module
        .maps
        .iter()
        .find(|v| v.name == needle)
        .unwrap()
}

pub struct Files;

#[derive(Debug)]
pub struct FileAccess {
    pub id: u64,
    pub process: String,
    pub path: String,
    pub ino: ino_t,
    pub read: usize,
    pub write: usize
}

impl EBPFGrain<'static> for Files {
    fn loaded(&mut self, module: &mut Module) {
        let actionlist = find_map_by_name(module, "actionlist");

        let mut record = _data_action {
            action: ACTION_RECORD,
        };
        let mut ino = metadata("/").unwrap().ino();
        actionlist.set(
            &mut ino as *mut ino_t as VoidPtr,
            &mut record as *mut _data_action as VoidPtr,
        );
    }

    fn code() -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/file.elf"))
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(move |raw| {
            let file = FileAccess::from(_data_volume::from(raw));
            let name = format!("file.{}", if file.write > 0 { "write" } else { "read" });
            let vol = if file.write > 0 {
                file.write
            } else {
                file.read
            };

            Some(Message::Single(Measurement::new(
                COUNTER | HISTOGRAM,
                name,
                Unit::Byte(vol as u64),
                file.to_tags(),
            )))
        })
    }
}

impl From<_data_volume> for FileAccess {
    fn from(data: _data_volume) -> FileAccess {
        let ino = data.file.path[0].ino;
        let mut path_segments = data.file.path.to_vec();
        path_segments.reverse();
        let path = path_segments
            .iter()
            .map(|s| to_string(unsafe { &*(&s.name as *const [i8] as *const [u8]) }))
            .collect::<Vec<String>>()
            .join("/");

        FileAccess {
            id: data.file.id,
            process: to_string(unsafe { &*(&data.file.comm as *const [i8] as *const [u8]) }),
            path,
            ino,
            read: data.read,
            write: data.write
        }
    }
}

impl ToTags for FileAccess {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("task_id", self.id.to_string());
        tags.insert("process", self.process);
        tags.insert("path", self.path);
        tags.insert("ino", self.ino.to_string());

        tags
    }
}
