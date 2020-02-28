
#![allow(non_camel_case_types)]

use std::ffi::CStr;
use std::fs::metadata;
use std::os::raw::c_char;
use std::os::unix::fs::MetadataExt;

use redbpf::{Module, HashMap};

use crate::grains::*;

use ingraind_probes::file::{Access, FileAccess as RawFileAccess};

type ino_t = u64;

//const ACTION_IGNORE: u8 = 0;
const ACTION_RECORD: u8 = 1;

pub struct Files(pub FilesConfig);
#[derive(Serialize, Deserialize, Debug)]
pub struct FilesConfig {
    pub monitor_dirs: Vec<String>,
}

#[derive(Debug)]
pub struct FileAccess {
    pub id: u64,
    pub process: String,
    pub path: String,
    pub ino: ino_t,
    pub read: usize,
    pub write: usize,
}

impl EBPFProbe for Grain<Files> {
    fn attach(&mut self) -> MessageStreams {

        self.attach_kprobes()
    }
}

impl EBPFGrain<'static> for Files {
    fn code() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/ingraind-probes/target/release/bpf-programs/file/file.elf"
        ))
    }

    fn loaded(&mut self, module: &mut Module) {
        let actionlist = HashMap::<u64, u8>::new(find_map_by_name(module, "actionlist")).unwrap();

        let record = ACTION_RECORD;
        for dir in self.0.monitor_dirs.iter() {
            let ino = metadata(dir).unwrap().ino();
            actionlist.set(ino, record);
        }
    }

    fn get_handler(&self, _id: &str) -> EventCallback {
        Box::new(move |raw| {
            let raw_access = unsafe { std::ptr::read(raw.as_ptr() as *const RawFileAccess) };
            let file = FileAccess::from(raw_access);
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

impl From<RawFileAccess> for FileAccess {
    fn from(raw: RawFileAccess) -> FileAccess {
        let segments = raw.paths.0.to_vec();
        let path = segments
            .iter()
            .rev()
            .map(|s| unsafe {
                CStr::from_ptr(s.name.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<String>>()
            .join("/")
            .trim_start_matches('/')
            .to_string();

        let (read, write) = match raw.access {
            Access::Read(s) => (s, 0),
            Access::Write(s) => (0, s),
        };

        FileAccess {
            id: raw.tid as u64,
            process: to_string(unsafe { &*(&raw.comm as *const [c_char]) }),
            path,
            ino: raw.inode,
            read,
            write,
        }
    }
}

impl ToTags for FileAccess {
    fn to_tags(self) -> Tags {
        let mut tags = Tags::new();

        tags.insert("process_id", self.id.to_string());
        tags.insert("process_str", self.process);
        tags.insert("path_str", self.path);
        tags.insert("ino_id", self.ino.to_string());

        tags
    }
}
