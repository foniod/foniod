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

#define USER_LEN 16
#define PATH_DEPTH 5

struct _data_file {
  u64 id;
  u64 ts;
  char comm[TASK_COMM_LEN];
  u16 name_len;
  char name[PATH_DEPTH][DNAME_INLINE_LEN];
  u32 inode;
  char user[USER_LEN];
};

struct _data_volumes {
  u64 reads;
  u64 writes;
  u64 rbytes;
  u64 wbytes;
};

#endif
