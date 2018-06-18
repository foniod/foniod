// This file is loosely based on code at https://github.com/jvns/rust-bcc/
// Any similarities are probably not accidental.
//

use bpf_sys::perf_reader::*;
use bpf_sys::{bpf_open_perf_buffer, bpf_update_elem};

use cpus::{get_online, CpuId};
use {LoadError, Map, Result, VoidPtr};

use std::ffi::{CStr, CString, NulError};
use std::os::unix::io::RawFd;
use std::ptr::null_mut;

unsafe extern "C" fn raw_callback(pc: VoidPtr, ptr: VoidPtr, size: i32) {
    let slice = ::std::slice::from_raw_parts(ptr as *const u8, size as usize);
    // prevent unwinding into C code
    // no custom panic hook set, panic will be printed as is
    let _ = ::std::panic::catch_unwind(|| (*(*(pc as *mut PerfCallbackWrapper)).0)(slice));
}

pub type PerfCallback = Box<FnMut(&[u8]) + Send>;
struct PerfCallbackWrapper(PerfCallback);

pub struct PerfReader(pub RawFd, *mut perf_reader, Box<PerfCallbackWrapper>);
impl PerfReader {
    fn new(pid: i32, cpu: i32, page_cnt: i32, callback: PerfCallback) -> Result<PerfReader> {
        let mut wrapped_cb = Box::new(PerfCallbackWrapper(callback));
        let reader = unsafe {
            ::bpf_sys::bpf_open_perf_buffer(
                Some(raw_callback),
                None,
                wrapped_cb.as_mut() as *mut _ as VoidPtr,
                pid,
                cpu,
                page_cnt,
            ) as *mut perf_reader
        };

        if reader.is_null() {
            return Err(LoadError::BPF);
        }

        let fd = unsafe { perf_reader_fd(reader) };
        Ok(PerfReader(fd, reader, wrapped_cb))
    }
}

impl Drop for PerfReader {
    fn drop(&mut self) {
        unsafe { perf_reader_free(self.0 as VoidPtr) }
    }
}

pub struct PerfMap<'m> {
    map: &'m Map,
    page_count: u32,
    readers: Vec<(CpuId, PerfReader)>,
}

impl<'m> PerfMap<'m> {
    fn new(map: &'m Map, page_count: u32) -> Result<PerfMap<'m>> {

        Ok(PerfMap {
            map,
            page_count,
            readers: vec![],
        })
    }

    fn poll(&mut self) {}
}
