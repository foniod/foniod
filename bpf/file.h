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

#ifndef __FILE_H
#define __FILE_H

#include <linux/kconfig.h>
#include <linux/types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/dcache.h>
#include <linux/stat.h>
#include <linux/ptrace.h>
#pragma clang diagnostic pop

#define PATH_DEPTH 8
#define ACTION_IGNORE 0
#define ACTION_RECORD 1

struct _data_action {
  u8 action;
};

struct _data_path_segment {
  u64 ino;
  char name[DNAME_INLINE_LEN];
};

struct _data_file {
  u64 id;
  u64 ts;
  u64 key;
  char comm[TASK_COMM_LEN];
  struct _data_path_segment path[PATH_DEPTH];
};

struct _data_volumes {
  u64 reads;
  u64 writes;
  u64 rbytes;
  u64 wbytes;
};

#endif
