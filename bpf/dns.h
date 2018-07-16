#ifndef __DNS_H
#define __DNS_H

#include <linux/kconfig.h>
#include <linux/types.h>

struct _data_dns_query {
  u16 id;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  char address[255];
  u16 qtype;
  u16 qclass;
};

#endif
