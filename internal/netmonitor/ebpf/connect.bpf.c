//go:build ignore
// +build ignore

// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// Data emitted per connect attempt
struct connect_event {
    __u64 ts_ns;
    __u64 cookie;
    __u32 pid;
    __u32 tgid;
    __u16 sport;
    __u16 dport;
    __u8  family; // AF_INET / AF_INET6
    __u8  protocol; // IPPROTO_TCP
    __u8  pad[6];
    union {
        __u32 ipv4;
        __u8  ipv6[16];
    } dst;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

static __always_inline int emit_event(struct sock *sk) {
    if (!sk)
        return 0;

    struct connect_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    ev->ts_ns = bpf_ktime_get_ns();
    ev->cookie = bpf_get_socket_cookie(sk);
    ev->pid = bpf_get_current_pid_tgid() >> 32; // tgid
    ev->tgid = bpf_get_current_pid_tgid();
    ev->sport = sport;
    ev->dport = bpf_ntohs(dport);
    ev->family = family;
    ev->protocol = IPPROTO_TCP;

    if (family == AF_INET) {
        ev->dst.ipv4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&ev->dst.ipv6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    struct sock *sk = (struct sock *)ctx->sk;
    return emit_event(sk);
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx) {
    struct sock *sk = (struct sock *)ctx->sk;
    return emit_event(sk);
}

char LICENSE[] SEC("license") = "Apache-2.0";
