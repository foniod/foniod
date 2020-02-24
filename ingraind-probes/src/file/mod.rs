use cty::*;

pub const PATH_SEGMENT_LEN: usize = 32;
pub const PATH_LIST_LEN: usize = 11;

#[derive(Debug)]
#[repr(u64)]
pub enum Access {
    Read(usize),
    Write(usize)
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PathSegment {
    pub name: [u8; PATH_SEGMENT_LEN],
}

#[derive(Debug)]
#[repr(C)]
pub struct PathList(pub [PathSegment; PATH_LIST_LEN]);

#[derive(Debug)]
#[repr(C)]
pub struct FileAccess {
    pub tid: u32,
    pub access: Access,
    pub ts: u64,
    pub comm: [c_char; 16],
    pub inode: u64,
    pub paths: PathList,

}
