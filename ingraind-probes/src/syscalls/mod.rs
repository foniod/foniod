use cty::*;

#[repr(C)]
#[derive(Debug)]
pub struct SyscallTracepoint {
  pub id: c_ulonglong,
  pub syscall_nr: c_ulonglong,
  pub comm: [c_char; 16usize],
}