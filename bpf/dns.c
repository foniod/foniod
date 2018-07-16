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

#include "dns.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#include <net/inet_sock.h>
#pragma clang diagnostic pop

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

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

static __inline__
s8 parse_dns_packet(struct xdp_md *ctx, void *buffer, void *data_end, struct _data_dns_query *query) {
  struct ethhdr *eth = (struct ethhdr *) buffer;
  struct iphdr *ip;
  struct udphdr *udp;
  void *dns;

  ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
  udp = (struct udphdr *) (ip + 1);

  /* dns header */
  if (udp + 1 > data_end) {
    return -7;
  }

  /* Skip non-802.3 protocols.
     unlikely(next_proto < ETH_P_802_3_MIN) ||
     TODO: anything that's not IP4 is not supported for now */
	if (!(eth->h_proto == bpf_htons(ETH_P_IP)
        && ip->protocol == IPPROTO_UDP
        )) {
		return -6;
  }

  /* 12 byte header + 253 qname + 2 qtype + 2 qclass */
  /* if (udp->len > 269) { */
  /*   return false; */
  /* } */

  query->saddr = ip->saddr;
  query->daddr = ip->daddr;
  query->sport = udp->source;
  query->dport = udp->dest;

  dns = buffer + sizeof(struct ethhdr)
    + sizeof(struct udphdr)
    + (ip->ihl * 4);
  if (dns + 12 > data_end) {
    return -5;
  }

  query->id = *(u16 *) dns;
  dns += 2;

  /* require standard query (QR=1, OPCODE=0, AA=x, TC=x, RD=x, RA=x, RCODE=x) */
  if (*((u8*) dns) >> 3 != 0x10) {
    return -4;
  }
  dns += 2;

  /* QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0 */
  if(*((u64 *) dns) != 0x0000000001000100) {
    return -3;
  }
  dns += 8;

  #pragma clang loop unroll(full)
  for (u8 i = 0; i < 253; i++) {
    if (dns + 1 > data_end) {
      return -2;
    }
    u8 b = *(u8 *) dns++;

    query->address[i] = b;
    if (b == 0) {
      break;
    }
  }

  if (dns + 4 > data_end) {
    return -1;
  }
  query->qtype = *(u16 *) dns;
  query->qtype = query->qtype;
  dns += 2;

  query->qclass = *(u16 *) dns;
  query->qclass = query->qclass;

  return 0;
}

SEC("xdp/dns_queries")
int report_dns_queries(struct xdp_md *ctx)
{
  u32 cpu = bpf_get_smp_processor_id();

  struct _data_dns_query data = {};
  if (parse_dns_packet(ctx,
                       (void *)(unsigned long) ctx->data,
                       (void *)(unsigned long) ctx->data_end,
                       &data) == 0) {
    bpf_perf_event_output(ctx, &dns_queries, cpu, &data, sizeof(data));
  }

  return XDP_PASS;
};
