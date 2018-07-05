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

#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/udp_volume") udp_volume = {
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

SEC("kprobe/udp_sendmsg")
int trace_sendmsg_entry(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
  struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
  size_t size = (size_t) PT_REGS_PARM3(ctx);

  struct _data_volume data = {
    .conn = get_connection_details(&sk, pid),
    .send = size,
    .recv = 0
  };

  if (data.conn.dport == (53 << 8)) {
    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &udp_volume, cpu, &data, sizeof(data));
  }

	return 0;
};

SEC("kprobe/udp_rcv")
int trace_recvmsg_entry(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
  struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
  u32 size = 0;
  struct sock *sk;

  bpf_probe_read(&sk, sizeof(void *), &skb->sk);
  bpf_probe_read(&size, sizeof(u32), &skb->len);

  struct _data_volume data = {
    .conn = get_connection_details(&sk, pid),
    .send = 0,
    .recv = size
  };

  if (data.conn.dport == (53 << 8)) {
    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &udp_volume, cpu, &data, sizeof(data));
  }

	return 0;
};
