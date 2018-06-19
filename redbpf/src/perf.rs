// This file is loosely based on code at https://github.com/jvns/rust-bcc/
// Any similarities are probably not accidental.
//

use bpf_sys::perf_reader::*;
use bpf_sys::{bpf_open_perf_buffer, bpf_update_elem};

use cpus::{self, CpuId};
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

struct PerfReader(*mut perf_reader);
impl PerfReader {
    fn new(
        pid: i32,
        cpu: i32,
        page_cnt: i32,
        callback: PerfCallback,
    ) -> Result<(PerfReader, RawFd, Box<PerfCallbackWrapper>)> {
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
        Ok((PerfReader(reader), fd, wrapped_cb))
    }
}

impl Drop for PerfReader {
    fn drop(&mut self) {
        unsafe { perf_reader_free(self.0 as VoidPtr) }
    }
}

pub struct PerfMap<'m> {
    map: &'m Map,
    page_count: i32,
    callbacks: Vec<Box<PerfCallbackWrapper>>,
    keys: Vec<CpuId>,
    readers: Vec<PerfReader>,
}

impl<'m> PerfMap<'m> {
    pub fn new<CB>(
        map: &'m mut Map,
        pid: i32,
        cpu: i32,
        page_count: i32,
        callback: CB,
    ) -> Result<PerfMap<'m>>
    where
        CB: Fn() -> PerfCallback,
    {
        let mut readers = vec![];
        let mut keys = vec![];
        let mut callbacks = vec![];

        // TODO: Abstract this out to a keying strategy, so keys can be used on
        // a per-pid/per-port/arbitrary basis
        for mut cpu in cpus::get_online()? {
            let (mut r, mut fd, c) = PerfReader::new(pid, cpu, page_count, callback())?;

            map.set(
                &mut cpu as *mut i32 as VoidPtr,
                &mut fd as *mut i32 as VoidPtr,
            );

            // Book-keeping. Same indexes will refer to the relevant object.
            // The primary reason of not using tuples here is that we can poll()
            // on readers as a **perf_reader, as seen below.
            readers.push(r);
            keys.push(cpu);
            callbacks.push(c);
        }

        Ok(PerfMap {
            map,
            page_count,
            readers,
            keys,
            callbacks,
        })
    }

    pub fn poll(&mut self, timeout: i32) {
        unsafe {
            perf_reader_poll(
                self.readers.len() as i32,
                self.readers.as_ptr() as *mut *mut perf_reader,
                timeout,
            );
        }
    }
}
