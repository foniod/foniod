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

#ifndef __CONNECTION_H
#define __CONNECTION_H

#include <linux/kconfig.h>
#include <linux/types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/inet_sock.h>
#include <net/sock.h>
#include <linux/ptrace.h>
#pragma clang diagnostic pop

#include <linux/version.h>
#include <linux/bpf.h>
#include "include/bpf_helpers.h"

struct _data_connect {
  u64 id;
  u64 ts;
  char comm[TASK_COMM_LEN];
  u32 saddr;
  u32 daddr;
  u16 dport;
  u16 sport;
};

struct _data_volume {
  struct _data_connect conn;
  size_t send;
  size_t recv;
};

static __inline__
struct _data_connect get_connection_details(struct sock **skpp, u64 pid) {
  struct _data_connect data = {};
  struct inet_sock *skp = inet_sk(*skpp);

  data.id = pid;
  data.ts = bpf_ktime_get_ns();

  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  bpf_probe_read(&data.saddr, sizeof(u32), &skp->inet_saddr);
  bpf_probe_read(&data.daddr, sizeof(u32), &skp->inet_daddr);
  bpf_probe_read(&data.dport, sizeof(u32), &skp->inet_dport);
  bpf_probe_read(&data.sport, sizeof(u32), &skp->inet_sport);

  return data;
}

#endif
