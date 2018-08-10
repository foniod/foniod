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

struct bpf_map_def SEC("maps/calltrack") calltrack = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct file *),
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

__inline_fn
int track_file_access(struct pt_regs *ctx,  u8 is_read)
{
  u64 tid = bpf_get_current_pid_tgid();
  struct file **filep = (struct file **) bpf_map_lookup_elem(&calltrack, &tid);
  if (filep == 0) {
    return 0;
  }

  struct file *file = *filep;
  struct path path;
  struct inode *inode;
  struct dentry *de, *de_cur;
  unsigned long i_ino;
  umode_t mode;

  size_t size = (size_t) PT_REGS_RC(ctx);
  if (size == 0) {
    return 0;
  }

  int check = 0;
  check |= bpf_probe_read(&path, sizeof(path), (void *)&file->f_path);
  check |= bpf_probe_read(&inode, sizeof(inode), (void *)&file->f_inode);
  check |= bpf_probe_read(&mode, sizeof(mode), (void *)&inode->i_mode);

  // Only track regular files for now
  if (check != 0 || !S_ISREG(mode)) {
    return 0;
  }
  de = de_cur = path.dentry;

  struct _data_volume vol = {
      .read = is_read ? size : 0,
      .write = is_read ? 0 : size
  };

  struct _data_file *info = &vol.file;
  info->id = tid;
  info->ts = bpf_ktime_get_ns();

  bool should_record = false;
  #pragma clang loop unroll(full)
  for (u8 i = 0; i < PATH_DEPTH; i++) {
    check |= bpf_probe_read(&info->path[i].name,
                            sizeof(info->path[i].name),
                            (void *)&de->d_iname);
    check |= bpf_probe_read(&inode, sizeof(inode), (void *)&de->d_inode);
    check |= bpf_probe_read(&i_ino, sizeof(i_ino), (void *)&inode->i_ino);
    check |= bpf_probe_read(&de, sizeof(void *), (void *)&de_cur->d_parent);
    if (check != 0) {
      return 0;
    }

    info->path[i].ino = i_ino;
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

  u32 cpu = bpf_get_smp_processor_id();
  bpf_get_current_comm(&info->comm, sizeof(info->comm));
  bpf_perf_event_output(ctx, &rw, cpu, &vol, sizeof(vol));

  return 0;
};

SEC("kprobe/vfs_read")
int trace_kread_entry(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
  struct file *f = (void *) PT_REGS_PARM1(ctx);
  bpf_map_update_elem(&calltrack, &pid, &f, BPF_ANY);
  return 0;
}

SEC("kprobe/vfs_write")
int trace_kwrite_entry(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
  struct file *f = (void *) PT_REGS_PARM1(ctx);
  bpf_map_update_elem(&calltrack, &pid, &f, BPF_ANY);
  return 0;
}

SEC("kretprobe/vfs_read")
int trace_kread_exit(struct pt_regs *ctx)
{
  return track_file_access(ctx, 1);
}

SEC("kretprobe/vfs_write")
int trace_kwrite_exit(struct pt_regs *ctx)
{
  return track_file_access(ctx, 0);
}
