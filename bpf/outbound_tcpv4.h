#ifndef __OUTBOUND_TCPV4_H
#define __OUTBOUND_TCPV4_H

#include <linux/kconfig.h>
#include <linux/types.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop

struct _data_connect {
  u64 id;
  u64 ts;
  char comm[TASK_COMM_LEN];
  u32 saddr;
  u32 daddr;
  u16 dport;
};

#endif
