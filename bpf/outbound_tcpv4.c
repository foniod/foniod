#include "outbound_tcpv4.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#pragma clang diagnostic pop

#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(events);

int trace_outbound_entry(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);

	return 0;
};

int trace_outbound_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
  struct _data_connect data = {};

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

  data.id = pid;
  data.ts = bpf_ktime_get_ns();

  bpf_get_current_comm(&data.comm, sizeof(data.comm));

	// pull in details
	struct sock *skp = *skpp;
	data.saddr = skp->__sk_common.skc_rcv_saddr;
	data.daddr = skp->__sk_common.skc_daddr;
	data.dport = skp->__sk_common.skc_dport;

  events.perf_submit(ctx, &data, sizeof(data));

	currsock.delete(&pid);

	return 0;
}
