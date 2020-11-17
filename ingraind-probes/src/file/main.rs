#![no_std]
#![no_main]
use ingraind_probes::file::{
    Access, FileAccess, PathList, PathSegment, PATH_LIST_LEN, PATH_SEGMENT_LEN,
};
use redbpf_probes::kprobe::prelude::*;
use unroll::unroll_for_loops;

enum AccessType {
    Read,
    Write,
}

program!(0xFFFFFFFE, "GPL");

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;

#[map("actionlist")]
static mut actionlist: HashMap<u64, u8> = HashMap::with_max_entries(10240);

#[map("files")]
static mut files: HashMap<u64, *const file> = HashMap::with_max_entries(10240);

#[map("rw")]
static mut rw: PerfMap<FileAccess> = PerfMap::with_max_entries(1024);

#[kprobe("vfs_read")]
pub fn trace_read_entry(regs: Registers) {
    let tid = bpf_get_current_pid_tgid();
    unsafe {
        let f = regs.parm1() as *const file;
        files.set(&tid, &f);
    }
}

#[kretprobe("vfs_read")]
pub fn trace_read_exit(regs: Registers) {
    track_file_access(regs, AccessType::Read);
}

#[kprobe("vfs_write")]
pub fn trace_write_entry(regs: Registers) {
    let tid = bpf_get_current_pid_tgid();
    unsafe {
        let f = regs.parm1() as *const file;
        files.set(&tid, &f);
    }
}

#[kretprobe("vfs_write")]
pub fn trace_write_exit(regs: Registers) {
    track_file_access(regs, AccessType::Write);
}

#[inline]
fn track_file_access(regs: Registers, access_type: AccessType) {
    let _ = do_track_file_access(regs, access_type);
}

#[inline]
fn do_track_file_access(regs: Registers, access_type: AccessType) -> Option<()> {
    let tid = bpf_get_current_pid_tgid();

    let size = regs.rc() as usize;
    if size == 0 {
        return None;
    }
    let file = unsafe { &**files.get(&tid)? };
    let path = file.f_path()?;
    let inode = file.f_inode()?;
    let inode = unsafe { &*inode };
    let i_no = inode.i_ino()?;
    let mode = inode.i_mode()?;
    if (mode & S_IFMT) != S_IFREG {
        return None;
    }

    let access = match access_type {
        AccessType::Read => Access::Read(size),
        AccessType::Write => Access::Write(size),
    };
    let mut event = FileAccess {
        tid: (tid >> 32) as u32,
        access,
        ts: bpf_ktime_get_ns(),
        comm: bpf_get_current_comm(),
        inode: i_no,
        paths: PathList(
            [PathSegment {
                name: [0u8; PATH_SEGMENT_LEN],
            }; PATH_LIST_LEN],
        ),
    };

    if let Some(InodePolicy::Record) = dentry_to_path(path.dentry, &mut event.paths) {
        unsafe {
            rw.insert(regs.ctx, &event);
        }
    }

    Some(())
}

#[inline]
#[unroll_for_loops]
fn dentry_to_path(mut dentry: *mut dentry, path_list: &mut PathList) -> Option<InodePolicy> {
    if dentry.is_null() {
        return None;
    }

    let mut policy = None;
    for i in 0..8 {
        let de = unsafe { &*dentry };

        // a nested policy overrides a parent one, eg: you can watch /etc/passwd
        // but ignore everyting else in /etc
        let inode = de.d_inode()?;
        if policy.is_none() {
            policy = policy_for_inode(&unsafe { &*inode }.i_ino()?);
        }

        let segment = &mut path_list.0[i];
        let name = de.d_name()?;
        let read = unsafe {
            bpf_probe_read_str(
                segment.name.as_mut_ptr() as *mut _,
                PATH_SEGMENT_LEN as i32,
                name.name as *const _,
            )
        };
        if read < 0 {
            return None;
        }

        let tmp = de.d_parent()?;
        if tmp == dentry {
            return policy;
        }
        dentry = tmp;
    }

    policy
}

enum InodePolicy {
    Record,
    Ignore,
}

#[inline]
fn policy_for_inode(inode: &u64) -> Option<InodePolicy> {
    use InodePolicy::*;

    match unsafe { actionlist.get(inode) } {
        Some(0) => Some(Ignore),
        Some(1) => Some(Record),
        _ => None,
    }
}
