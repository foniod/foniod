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

#include "syscall.h"

#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/syscall_tp_trigger") syscall_event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10240,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/host_pid") host_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u32),
    .max_entries = 16,
    .pinning = 0,
    .namespace = "",
};


// Version number to stay compatible with gobpf-elf-loader
// This should be resolved to running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";

SEC("kprobe/syscall_enter")
int syscall_tp_handler(struct pt_regs *ctx) {
  u8 key = 1;
  u32 *ignore_pid = bpf_map_lookup_elem(&host_pid, &key);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  if (ignore_pid != 0 && (pid_tgid >> 32) == *ignore_pid) {
    return 0;
  }
  
  struct _data_syscall_tracepoint data = {};
  data.syscall_nr = PT_REGS_RC(ctx);
  data.id = pid_tgid >> 32;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  u32 cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &syscall_event, cpu, &data, sizeof(data));

  return 0;
}
