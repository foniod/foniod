#ifndef __ROUTER_H
#define __ROUTER_H

#include <linux/kconfig.h>
#include <linux/types.h>

struct _data_exchange {
  u16 size;
  u32 saddr;
  u32 daddr;
  u16 dport;
  u16 sport;
  u8 proto;
};

#endif
