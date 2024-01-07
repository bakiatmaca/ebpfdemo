// +build ignore

#include "main.bpf.h"

#define AF_INET 2

struct eventtcp {
	u8 comm[16];
	u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct eventtcp *unused __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} eventtcp SEC(".maps");


SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	struct eventtcp *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&eventtcp, sizeof(struct eventtcp), 0);
	if (!tcp_info) {
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
