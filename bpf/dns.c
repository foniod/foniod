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

struct bpf_map_def SEC("maps/dns_queries") dns_queries = {
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

SEC("xdp/dns_queries")
int report_dns_queries(struct xdp_md *ctx)
{
	u64 pid = 1;
  u32 cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &dns_queries, cpu, &pid, sizeof(pid));

	struct ethhdr *eth = (struct ethhdr *)(long)ctx->data;
	__u16 proto;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_IP))
		return XDP_DROP;
	else if (proto == bpf_htons(ETH_P_IPV6))
		return XDP_DROP;
	else
		/* Pass the rest to stack, we might later do more
		 * fine-grained filtering here.
		 */
    return XDP_DROP;
};
