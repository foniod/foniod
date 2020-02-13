#![no_std]
#![no_main]

#[macro_use]
extern crate redbpf_probes;

use cty::*;

use redbpf_macros::{kprobe, kretprobe, map, program};
use redbpf_probes::bindings::*;
use redbpf_probes::helpers::*;
use redbpf_probes::kprobe::*;
use redbpf_probes::maps::*;

use ingraind_probes::network::{Connection, Message};

program!(0xFFFFFFFE, "GPL");

#[map("task_to_socket")]
static mut task_to_socket: HashMap<u64, *const sock> = HashMap::with_max_entries(10240);

#[map("ip_connections")]
static mut ip_connections: PerfMap<Connection> = PerfMap::with_max_entries(1024);

#[map("ip_volume")]
static mut ip_volumes: PerfMap<Message> = PerfMap::with_max_entries(1024);

#[kprobe("tcp_v4_connect")]
pub extern "C" fn connect_enter(regs: Registers) -> i32 {
    store_socket(regs)
}

#[kretprobe("tcp_v4_connect")]
pub extern "C" fn connect(regs: Registers) -> i32
{
    match conn_details(regs) {
        Some(c) => unsafe {
            ip_connections.insert(regs.ctx, c);
            0
        },
        None => 0,
    }
}

#[kprobe("tcp_sendmsg")]
pub extern "C" fn send_enter(regs: Registers) -> i32 {
    store_socket(regs)
}

#[kretprobe("tcp_sendmsg")]
pub extern "C" fn send_exit(regs: Registers) -> i32 {
    trace_message(regs, Message::Send)
}

#[kprobe("tcp_recvmsg")]
pub extern "C" fn recv_enter(regs: Registers) -> i32 {
    store_socket(regs)
}

#[kretprobe("tcp_recvmsg")]
pub extern "C" fn recv_exit(regs: Registers) -> i32 {
    trace_message(regs, Message::Receive)
}

#[kprobe("udp_sendmsg")]
pub extern "C" fn udp_send_enter(regs: Registers) -> i32 {
    trace_message(regs, Message::Send)
}

#[kprobe("udp_rcv")]
pub extern "C" fn udp_rcv_enter(regs: Registers) -> i32 {
    trace_message(regs, Message::Receive)
}

#[inline(always)]
fn store_socket(regs: Registers) -> i32 {
    unsafe { task_to_socket.set(bpf_get_current_pid_tgid(), regs.parm1() as *const sock) };

    0
}

#[inline(always)]
fn trace_message(regs: Registers, direction: fn(Connection, u16) -> Message) -> i32 {
    let len = regs.parm3() as u16;
    let conn = conn_details(regs);

    match conn {
        Some(c) => unsafe {
            ip_volumes.insert(regs.ctx, direction(c, len));
            0
        },
        None => 0,
    }
}

#[inline(always)]
pub fn conn_details(_regs: Registers) -> Option<Connection> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let socket = unsafe { match task_to_socket.get(pid_tgid) {
        Some(s) => &**s,
        None => return None,
    }};

    let pid = (pid_tgid >> 32) as u32;
    let ts = bpf_ktime_get_ns();
    let family = socket.skc_family();

    let mut daddr = in6_addr {
        in6_u: in6_addr__bindgen_ty_1 {
            u6_addr32: [0, 0, 0, 0],
        },
    };
    let mut saddr = in6_addr {
        in6_u: in6_addr__bindgen_ty_1 {
            u6_addr32: [0, 0, 0, 0],
        },
    };

    if family as u32 == AF_INET6 {
        daddr = socket.skc_v6_daddr();
        saddr = socket.skc_v6_rcv_saddr();
    } else if family as u32 == AF_INET {
        let dest = socket.skc_daddr();
        let src = socket.skc_rcv_saddr();

        daddr = in6_addr {
            in6_u: in6_addr__bindgen_ty_1 {
                u6_addr32: [0, 0, 0xFFFF0000, dest],
            },
        };
        saddr = in6_addr {
            in6_u: in6_addr__bindgen_ty_1 {
                u6_addr32: [0, 0, 0xFFFF0000, src],
            },
        };
    }

    let dport = socket.skc_dport();
    let sport = socket.skc_num();

    let typ = {
        let typ = bpf_probe_read!(&socket._bitfield_1 as *const _ as *const u32);

        (typ & SK_FL_PROTO_MASK) >> SK_FL_PROTO_SHIFT
    };

    unsafe {
        task_to_socket.delete(pid_tgid);
    }

    Some(Connection {
        pid,
        ts,
        comm: bpf_get_current_comm(),
        saddr: saddr.into(),
        daddr: daddr.into(),
        sport: sport as u32,
        dport: dport as u32,
        typ,
    })
}
