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

#include "include/bpf_helpers.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#include <net/sock.h>
#include <net/inet_sock.h>
#pragma clang diagnostic pop

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <uapi/linux/tcp.h>

#include <linux/skbuff.h>

#define ETH_HLEN 14

// Version number to stay compatible with gobpf-elf-loader
// This should be resolved to running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";

SEC("socketfilter/tls_handshake")
int tls_handshake(struct __sk_buff *skb)
{
  u16 eth_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
  u8 ip_proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

  /* Skip non-802.3 protocols.
     unlikely(next_proto < ETH_P_802_3_MIN) ||
     TODO: anything that's not IP4 is not supported for now */
	if (!(eth_proto == ETH_P_IP
        && ip_proto == IPPROTO_TCP))
  {
		goto IGNORE;
  }

  u8 iphlen = (load_byte(skb, ETH_HLEN) & 0x0F) << 2;
  u8 tcplen = ((load_byte(skb, ETH_HLEN + iphlen + 12)) >> 4) << 2;

  u8 tls = ETH_HLEN
    + iphlen
    + tcplen;

  /* #pragma clang loop unroll(full) */
	/* for (u8 i = 0; i < 5; i++) { */
	/* 	buf[i] = load_byte(skb, tls + i); */
	/* } */

  u8 content_type = load_byte(skb, tls);
  u8 vmajor = load_byte(skb, tls+1);
  u8 vminor = load_byte(skb, tls+2);

  if (content_type == 0x16 &&
      vmajor <= 0x03 && vminor <= 0x04) {
    goto USERSPACE;
  }

 IGNORE:
  return 0;
 USERSPACE:
  return -1;
};
