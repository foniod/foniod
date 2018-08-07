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

#include "file.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/stat.h>
#pragma clang diagnostic pop

#include <linux/version.h>
#include <linux/bpf.h>
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/actionlist") actionlist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct _data_action),
    .max_entries = 102400,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/volumes") volumes = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct _data_volumes),
    .max_entries = 1024000,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/calltrack") calltrack = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 10240,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/rw") rw = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10240,
    .pinning = 0,
    .namespace = "",
};

// Version number to stay compatible with gobpf-elf-loader
// This should be resolved to running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";

static __inline__
struct _data_volumes* track_file_access(struct pt_regs *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
  u64 tid = bpf_get_current_pid_tgid();

  struct file *file = (struct file *) PT_REGS_PARM1(ctx);
  struct path path;
  struct inode *inode;
  struct dentry *de, *de_cur;
  unsigned long i_ino;
  umode_t mode;

  int check = 0;
  check |= bpf_probe_read(&path, sizeof(path), (void *)&file->f_path);
  check |= bpf_probe_read(&inode, sizeof(inode), (void *)&file->f_inode);
  check |= bpf_probe_read(&mode, sizeof(mode), (void *)&inode->i_mode);

  // Only track regular files for now
  if (check != 0 || !S_ISREG(mode)) {
    return 0;
  }

  de = de_cur = path.dentry;
  struct _data_file info = {
    .id = tid,
    .ts = bpf_ktime_get_ns()
  };

  bool should_record = false;
  #pragma clang loop unroll(full)
  for (u8 i = 0; i < PATH_DEPTH; i++) {
    check |= bpf_probe_read(&info.path[i].name,
                            sizeof(info.path[i].name),
                            (void *)&de->d_iname);
    check |= bpf_probe_read(&inode, sizeof(inode), (void *)&de->d_inode);
    check |= bpf_probe_read(&i_ino, sizeof(i_ino), (void *)&inode->i_ino);
    check |= bpf_probe_read(&de, sizeof(void *), (void *)&de_cur->d_parent);
    if (check != 0) {
      return 0;
    }

    info.path[i].ino = i_ino;
    struct _data_action *ptr = (struct _data_action *) bpf_map_lookup_elem(&actionlist, &i_ino);
    if (ptr != 0) {
      if (ptr->action == ACTION_IGNORE) {
        return 0;
      } else if (ptr->action == ACTION_RECORD) {
        should_record = true;
        break;
      }
    }

    if (de_cur == de) {
      break;
    }

    de_cur = de;
  }
  if (!should_record) {
    return 0;
  }

  bpf_get_current_comm(&info.comm, sizeof(info.comm));
  info.key = tid | info.path[0].ino;

  struct _data_volumes *vol = bpf_map_lookup_elem(&volumes, &info.path[0].ino);
  if (vol == 0) {
    struct _data_volumes v = {};
    check = bpf_map_update_elem(&volumes, &info.key, &v, 0);
    vol = bpf_map_lookup_elem(&volumes, &info.key);
    if (check != 0 || vol == 0) {
      return 0;
    }

    bpf_perf_event_output(ctx, &rw, cpu, &info, sizeof(info));
  }

  return vol;
};

SEC("kprobe/vfs_read")
int trace_kread_entry(struct pt_regs *ctx)
{
  struct _data_volumes *vol = track_file_access(ctx);
  if (vol != 0) {
    vol->reads++;
    vol->rbytes += (size_t) PT_REGS_PARM3(ctx);
  }

  return 0;
}

SEC("kprobe/vfs_write")
int trace_kwrite_entry(struct pt_regs *ctx)
{
  struct _data_volumes *vol = track_file_access(ctx);
  if (vol != 0) {
    vol->writes++;
    vol->wbytes += (size_t) PT_REGS_PARM3(ctx);
  }

  return 0;
};
