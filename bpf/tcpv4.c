/*
 *  Copyright (C) 2018 Authors of RedSift
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "connection.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#include <net/inet_sock.h>
#pragma clang diagnostic pop

#include <linux/version.h>
#include <linux/bpf.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/currsock") currsock = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 10240,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp4_connections") tcp4_connections = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp4_volume") tcp4_volume = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

// Version number to stay compatible with gobpf-elf-loader
// This should be resolved to running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";

__inline_fn
int store_to_task_map(struct bpf_map_def *map, void *ptr)
{
	u64 pid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(map, &pid, &ptr, BPF_ANY);
  return 0;
}

SEC("kprobe/tcp_sendmsg")
int trace_sendmsg_entry(struct pt_regs *ctx)
{
  return store_to_task_map(&currsock, (void *) PT_REGS_PARM1(ctx));
};

SEC("kprobe/tcp_recvmsg")
int trace_recvmsg_entry(struct pt_regs *ctx)
{
  return store_to_task_map(&currsock, (void *) PT_REGS_PARM1(ctx));
};

SEC("kprobe/tcp_v4_connect")
int trace_outbound_entry(struct pt_regs *ctx)
{
  return store_to_task_map(&currsock, (void *) PT_REGS_PARM1(ctx));
};

#define SEND 1
#define RECV 2

__inline_fn
int traffic_volume(struct bpf_map_def *state, struct bpf_map_def *output, struct pt_regs *ctx, u8 direction)
{
	u64 pid = bpf_get_current_pid_tgid();
  int size = (int) PT_REGS_RC(ctx);

	struct sock **skpp = bpf_map_lookup_elem(state, &pid);
	if (skpp == 0) {
		return 0;	
	}

  if (size <= 0) {
    bpf_map_delete_elem(state, &pid);
    return 0;
  }

  struct _data_volume data = {
                              .conn = get_connection_details(skpp, pid),
                              .send = direction == SEND ? size : 0,
                              .recv = direction == RECV ? size : 0
  };

  u32 cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, output, cpu, &data, sizeof(data));

  bpf_map_delete_elem(state, &pid);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int trace_sendmsg_return(struct pt_regs *ctx)
{
  return traffic_volume(&currsock, &tcp4_volume, ctx, SEND);
};

SEC("kretprobe/tcp_recvmsg")
int trace_recvmsg_return(struct pt_regs *ctx)
{
  return traffic_volume(&currsock, &tcp4_volume, ctx, RECV);
};

SEC("kretprobe/tcp_v4_connect")
int trace_outbound_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&currsock, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
    bpf_map_delete_elem(&currsock, &pid);
    return 0;
	}

  struct _data_connect data = get_connection_details(skpp, pid);

  if (data.saddr == 0 || data.daddr == 0 || data.dport == 0 || data.sport == 0) {
    bpf_map_delete_elem(&currsock, &pid);
    return 0;
  }

	u32 cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &tcp4_connections, cpu, &data, sizeof(data));

  bpf_map_delete_elem(&currsock, &pid);
	return 0;
}
