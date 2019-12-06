#![no_std]
#![no_main]

#[macro_use]
extern crate redbpf_probes;

use cty::*;

use redbpf_macros::{helpers, kprobe, kretprobe, map, program};
use redbpf_probes::bindings::*;
use redbpf_probes::kprobe::*;
use redbpf_probes::maps::*;

use ingraind_probes::connection::{Connection, Message};

// Use the types you're going to share with userspace, eg:
// use ingraind-probes::connection::SomeEvent;

program!(0xFFFFFFFE, "GPL");

#[map("task_to_socket")]
static mut task_to_socket: HashMap<u64, *const sock> = HashMap::with_max_entries(10240);

#[map("ip_connections")]
static mut ip_connections: PerfMap<Connection> = PerfMap::with_max_entries(1024);

#[map("ip_volume")]
static mut ip_volumes: PerfMap<Message> = PerfMap::with_max_entries(1024);

#[kprobe("tcp_v4_connect")]
pub extern "C" fn connect_enter(ctx: *mut c_void) -> i32 {
    store_socket(ctx)
}

#[kretprobe("tcp_v4_connect")]
pub extern "C" fn connect(ctx: *mut c_void) -> i32 {
    match conn_details(ctx) {
        Some(c) => unsafe {
            ip_connections.insert(ctx, c);
            0
        },
        None => 0,
    }
}

#[kprobe("tcp_sendmsg")]
pub extern "C" fn send_enter(ctx: *mut c_void) -> i32 {
    store_socket(ctx)
}

#[kprobe("tcp_recvmsg")]
pub extern "C" fn recv_enter(ctx: *mut c_void) -> i32 {
    trace_message(ctx)
}

#[kprobe("udp_sendmsg")]
pub extern "C" fn udp_send_enter(ctx: *mut c_void) -> i32 {
    store_socket(ctx)
}

#[kretprobe("udp_sendmsg")]
pub extern "C" fn udp_send_exit(ctx: *mut c_void) -> i32 {
    trace_message(ctx)
}

#[inline(always)]
#[helpers]
fn store_socket(ctx: *mut c_void) -> i32 {
    let regs = Registers::from(ctx);
    unsafe { task_to_socket.set(bpf_get_current_pid_tgid(), regs.parm1() as *const sock) };

    0
}

#[inline(always)]
#[helpers]
fn trace_message(ctx: *mut c_void) -> i32 {
    let regs = Registers::from(ctx);
    let len = regs.parm3();
    let conn = conn_details(regs.parm1() as *mut c_void);

    match conn {
        Some(c) => unsafe {
            ip_volumes.insert(ctx, Message::Send(c, len));
            0
        },
        None => 0,
    }
}

#[inline(always)]
#[helpers]
pub fn conn_details(ctx: *mut c_void) -> Option<Connection> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let socket = match unsafe { task_to_socket.get(pid_tgid) } {
        Some(s) => s,
        None => return None,
    };

    let pid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let family = read_pointer::<u16>(ctx_field!((*socket).__sk_common.skc_family));

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
        daddr = read_pointer::<in6_addr>(ctx_field!((*socket).__sk_common.skc_v6_daddr));
        saddr = read_pointer::<in6_addr>(ctx_field!((*socket).__sk_common.skc_v6_rcv_saddr));
    } else if family as u32 == AF_INET {
        let dest = read_pointer::<u32>(ctx_field!(
            (*socket)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr
        ));
        let src = read_pointer::<u32>(ctx_field!(
            (*socket)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr
        ));

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

    let dport = read_pointer::<u16>(ctx_field!(
        (*socket)
            .__sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport
    ));
    let sport = read_pointer::<u16>(ctx_field!(
        (*socket)
            .__sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_num
    ));

    let typ = {
        let typ = read_pointer::<u32>(ctx_field!((*socket)._bitfield_1));

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
