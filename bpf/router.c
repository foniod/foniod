/*
 *  Copyright (C) 2019 Authors of RedSift
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

#include "router.h"
#include "include/bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#pragma clang diagnostic pop

#include <linux/skbuff.h>

struct bpf_map_def SEC("maps/traffic_stats") events = {
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
s8 packet(struct xdp_md *ctx, void *buffer, void *data_end, struct _data_exchange *data) {
  struct ethhdr *eth = (struct ethhdr *) buffer;
  struct iphdr *ip;
  struct udphdr *udp;
  struct tcphdr *tcp;

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    return -6;
  }

  ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));

  if (ip + 1 > data_end) {
    return -7;
  }

  data->size = data_end - buffer;
  data->saddr = ip->saddr;
  data->daddr = ip->daddr;
  data->proto = ip->protocol;

  if (ip->protocol == IPPROTO_UDP) {
    udp = (struct udphdr *) (ip + 1);

    if (udp + 1 > data_end) {
      return -7;
    }

    data->sport = udp->source;
    data->dport = udp->dest;
  }

  if (ip->protocol == IPPROTO_TCP) {
    tcp = (struct tcphdr *) (ip + 1);

    if (tcp + 1 > data_end) {
      return -7;
    }

    data->sport = tcp->source;
    data->dport = tcp->dest;
  }

  return 0;
}

SEC("xdp/dns_queries")
int report_dns_queries(struct xdp_md *ctx)
{
  u32 cpu = bpf_get_smp_processor_id();

  struct _data_exchange data = {};
  if (packet(ctx,
                       (void *)(unsigned long) ctx->data,
                       (void *)(unsigned long) ctx->data_end,
                       &data) == 0) {
    bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
  }

  return XDP_PASS;
};
