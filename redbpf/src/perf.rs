/*

static int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}
*/

use sys::perf::*;

use cpus::{self, CpuId};
use {LoadError, Map, Result, VoidPtr};

use std::os::unix::io::RawFd;
use std::mem;
use std::io;

use libc::{syscall, SYS_perf_event_open, c_int, c_ulong};

fn open_perf_buffer(pid: i32, cpu: u32, page_cnt: u32, cgroup: RawFd, flags: u32) -> Result<RawFd> {
    let attr = mem::zeroed::<perf_event_attr>();

    attr.config = perf_sw_ids_PERF_COUNT_SW_BPF_OUTPUT;
    attr.size = mem::size_of::<perf_event_attr>() as u32;
    attr.type_ = perf_type_id_PERF_TYPE_SOFTWARE;
    attr.sample_type = perf_event_sample_format_PERF_SAMPLE_RAW as u64;
    attr.__bindgen_anon_1.sample_period = 1;
    attr.__bindgen_anon_2.wakeup_events = 1;

    let pfd = syscall(SYS_perf_event_open, &attr as *const perf_event_attr, pid, cpu, cgroup, flags | PERF_FLAG_FD_CLOEXEC);
    if pfd < 0 {
        Err(LoadError::IO(io::Error::last_os_error()))
    } else {
        Ok(pfd as RawFd)
    }
}


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
            bpf_open_perf_buffer(
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

pub struct PerfMap {
    map: Map,
    page_count: i32,
    callbacks: Vec<Box<PerfCallbackWrapper>>,
    keys: Vec<CpuId>,
    readers: Vec<PerfReader>,
}

impl PerfMap {
    pub fn new<CB>(
        mut map: Map,
        pid: i32,
        cpu: i32,
        page_count: i32,
        callback: CB,
    ) -> Result<PerfMap>
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
