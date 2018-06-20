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

#include "outbound_tcpv4.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#pragma clang diagnostic pop

#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/currsock") currsock = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};


struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

/* BPF_HASH(currsock, u32, struct sock *); */
/* BPF_PERF_OUTPUT(events); */

// Version number to stay compatible with gobpf-elf-loader
// This should be resolved to running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";

SEC("kprobe/tcp_v4_connect")
int trace_outbound_entry(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
  struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);

	// stash the sock ptr for lookup on return
  bpf_map_update_elem(&currsock, &pid, &sk, BPF_ANY);

	return 0;
};

SEC("kretprobe/tcp_v4_connect")
int trace_outbound_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
  struct _data_connect data = {};

	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&currsock, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
    goto cleanup;
	}

  data.id = pid;
  data.ts = bpf_ktime_get_ns();

  bpf_get_current_comm(&data.comm, sizeof(data.comm));

	// pull in details
  struct sock *skp = *skpp;
	struct sock_common skc;

  ret = bpf_probe_read(&skc, sizeof(struct sock_common), skp);
  if (ret < 0) {
    goto cleanup;
  }

	data.saddr = skc.skc_rcv_saddr;
	data.daddr = skc.skc_daddr;
	data.sport = skc.skc_sport;
	data.dport = skc.skc_dport;

	u32 cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));

 cleanup:
  bpf_map_delete_elem(&currsock, &pid);
	return 0;
}
