use cty::*;

#[repr(C)]
pub struct Event {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub offset: u32,
    pub size: u32,
    pub data: [u8; 0]
}

#[cfg(not(feature = "probes"))]
impl Event {
    pub fn data(&self) -> &[u8] {
        unsafe {
            let base = self.data.as_ptr().add(self.offset as usize);
            core::slice::from_raw_parts(base, self.size as usize)
        }
    }
}