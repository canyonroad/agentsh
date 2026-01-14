//go:build ignore
// +build ignore

// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
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
    __u8  blocked; // 1 if denied by ebpf
    __u8  _pad2[7];
};

// Extracted context values to avoid passing ctx after modification
struct ctx_info {
    __u64 cgroup_id;
    __u8  family;
    __u16 dport;
    __u32 ipv4;
    __u8  ipv6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

struct allow_key {
    __u64 cgroup_id;
    __u8 family;
    __u8 protocol; // IPPROTO_TCP or IPPROTO_UDP, 0 = any
    __u16 dport;
    __u8 addr[16];
};

// map size tunables (overridable at compile time via -D)
#ifndef ALLOWLIST_MAX_ENTRIES
#define ALLOWLIST_MAX_ENTRIES 1024
#endif
#ifndef DENYLIST_MAX_ENTRIES
#define DENYLIST_MAX_ENTRIES ALLOWLIST_MAX_ENTRIES
#endif
#ifndef LPM_MAX_ENTRIES
#define LPM_MAX_ENTRIES 1024
#endif
#ifndef LPM_DENY_MAX_ENTRIES
#define LPM_DENY_MAX_ENTRIES LPM_MAX_ENTRIES
#endif
#ifndef DEFAULT_DENY_MAX_ENTRIES
#define DEFAULT_DENY_MAX_ENTRIES 1024
#endif

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ALLOWLIST_MAX_ENTRIES);
    __type(key, struct allow_key);
    __type(value, __u8);
} allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DENYLIST_MAX_ENTRIES);
    __type(key, struct allow_key);
    __type(value, __u8);
} denylist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_DENY_MAX_ENTRIES);
    __type(key, __u64); // cgroup id
    __type(value, __u8);
} default_deny SEC(".maps");

struct lpm4_key {
    __u32 prefixlen; // bits of (cgroup_id || addr || dport)
    __u64 cgroup_id;
    __u32 addr;
    __u16 dport;
};
struct lpm6_key {
    __u32 prefixlen; // bits of (cgroup_id || addr || dport)
    __u64 cgroup_id;
    __u8 addr[16];
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} lpm4_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} lpm6_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_DENY_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm4_key);
    __type(value, __u8);
} lpm4_deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LPM_DENY_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm6_key);
    __type(value, __u8);
} lpm6_deny SEC(".maps");

static __always_inline int emit_event(struct ctx_info *info, __u8 protocol, bool blocked) {
    struct connect_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->ts_ns = bpf_ktime_get_ns();
    // Generate unique cookie for pending approval tracking using random values
    ev->cookie = ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->tgid = bpf_get_current_pid_tgid();
    ev->sport = 0;
    ev->dport = info->dport;
    ev->family = info->family;
    ev->protocol = protocol;
    ev->blocked = blocked ? 1 : 0;

    if (info->family == AF_INET) {
        ev->dst.ipv4 = info->ipv4;
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(ev->dst.ipv6, info->ipv6, 16);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static __always_inline bool is_denied(struct ctx_info *info, __u8 protocol) {
    struct allow_key key = {};
    key.cgroup_id = info->cgroup_id;
    key.family = info->family;
    key.protocol = protocol;
    key.dport = info->dport;
    if (info->family == AF_INET) {
        __builtin_memcpy(key.addr, &info->ipv4, 4);
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(key.addr, info->ipv6, 16);
    }

    // Check exact protocol match first
    __u8 *val = bpf_map_lookup_elem(&denylist, &key);
    if (val)
        return true;

    // Check protocol-agnostic rule (protocol = 0)
    if (protocol != 0) {
        key.protocol = 0;
        val = bpf_map_lookup_elem(&denylist, &key);
        if (val)
            return true;
        key.protocol = protocol; // restore for CIDR checks
    }

    // Check CIDR LPM maps.
    if (info->family == AF_INET) {
        struct lpm4_key lk = {};
        lk.cgroup_id = key.cgroup_id;
        __builtin_memcpy(&lk.addr, &info->ipv4, 4);
        lk.dport = info->dport;
        lk.prefixlen = 64 + 32 + 16; // include port
        val = bpf_map_lookup_elem(&lpm4_deny, &lk);
        if (val)
            return true;
        // fallback to any-port prefix
        lk.prefixlen = 64 + 32;
        lk.dport = 0;
        val = bpf_map_lookup_elem(&lpm4_deny, &lk);
        if (val)
            return true;
    } else if (info->family == AF_INET6) {
        struct lpm6_key lk = {};
        lk.cgroup_id = key.cgroup_id;
        __builtin_memcpy(&lk.addr, info->ipv6, 16);
        lk.dport = info->dport;
        lk.prefixlen = 64 + 128 + 16; // include port
        val = bpf_map_lookup_elem(&lpm6_deny, &lk);
        if (val)
            return true;
        lk.prefixlen = 64 + 128;
        lk.dport = 0;
        val = bpf_map_lookup_elem(&lpm6_deny, &lk);
        if (val)
            return true;
    }
    return false;
}

static __always_inline bool allow(struct ctx_info *info, __u8 protocol) {
    struct allow_key key = {};
    key.cgroup_id = info->cgroup_id;
    key.family = info->family;
    key.protocol = protocol;
    key.dport = info->dport;
    if (info->family == AF_INET) {
        __builtin_memcpy(key.addr, &info->ipv4, 4);
    } else if (info->family == AF_INET6) {
        __builtin_memcpy(key.addr, info->ipv6, 16);
    }

    // Check exact protocol match first
    __u8 *val = bpf_map_lookup_elem(&allowlist, &key);
    if (val)
        return true;

    // Check protocol-agnostic rule (protocol = 0)
    if (protocol != 0) {
        key.protocol = 0;
        val = bpf_map_lookup_elem(&allowlist, &key);
        if (val)
            return true;
    }

    // Check CIDR LPM maps.
    if (info->family == AF_INET) {
        struct lpm4_key lk = {};
        lk.cgroup_id = key.cgroup_id;
        __builtin_memcpy(&lk.addr, &info->ipv4, 4);
        lk.dport = info->dport;
        lk.prefixlen = 64 + 32 + 16; // include port
        val = bpf_map_lookup_elem(&lpm4_allow, &lk);
        if (val)
            return true;
        // fallback to any-port prefix
        lk.prefixlen = 64 + 32;
        lk.dport = 0;
        val = bpf_map_lookup_elem(&lpm4_allow, &lk);
        if (val)
            return true;
    } else if (info->family == AF_INET6) {
        struct lpm6_key lk = {};
        lk.cgroup_id = key.cgroup_id;
        __builtin_memcpy(&lk.addr, info->ipv6, 16);
        lk.dport = info->dport;
        lk.prefixlen = 64 + 128 + 16; // include port
        val = bpf_map_lookup_elem(&lpm6_allow, &lk);
        if (val)
            return true;
        lk.prefixlen = 64 + 128;
        lk.dport = 0;
        val = bpf_map_lookup_elem(&lpm6_allow, &lk);
        if (val)
            return true;
    }
    return false;
}

static __always_inline bool is_default_deny(void) {
    __u64 k = bpf_get_current_cgroup_id();
    __u8 *v = bpf_map_lookup_elem(&default_deny, &k);
    return v && *v;
}

SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    // Read ctx values into local variables
    __u32 ip4 = ctx->user_ip4;
    __u32 port = ctx->user_port;

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET;
    info.dport = bpf_ntohs(port);
    info.ipv4 = ip4;

    bool denied = false;
    if (is_denied(&info, IPPROTO_TCP)) {
        denied = true;
    } else if (is_default_deny() && !allow(&info, IPPROTO_TCP)) {
        denied = true;
    }
    emit_event(&info, IPPROTO_TCP, denied);
    return denied ? 0 : 1;
}

SEC("cgroup/connect6")
int handle_connect6(struct bpf_sock_addr *ctx) {
    // Read ctx values into local variables
    __u32 port = ctx->user_port;
    __u32 ip6_0 = ctx->user_ip6[0];
    __u32 ip6_1 = ctx->user_ip6[1];
    __u32 ip6_2 = ctx->user_ip6[2];
    __u32 ip6_3 = ctx->user_ip6[3];

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET6;
    info.dport = bpf_ntohs(port);
    __u32 *dst = (__u32 *)info.ipv6;
    dst[0] = ip6_0;
    dst[1] = ip6_1;
    dst[2] = ip6_2;
    dst[3] = ip6_3;

    bool denied = false;
    if (is_denied(&info, IPPROTO_TCP)) {
        denied = true;
    } else if (is_default_deny() && !allow(&info, IPPROTO_TCP)) {
        denied = true;
    }
    emit_event(&info, IPPROTO_TCP, denied);
    return denied ? 0 : 1;
}

// UDP sendmsg hooks
SEC("cgroup/sendmsg4")
int handle_sendmsg4(struct bpf_sock_addr *ctx) {
    __u32 ip4 = ctx->user_ip4;
    __u32 port = ctx->user_port;

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET;
    info.dport = bpf_ntohs(port);
    info.ipv4 = ip4;

    bool denied = false;
    if (is_denied(&info, IPPROTO_UDP)) {
        denied = true;
    } else if (is_default_deny() && !allow(&info, IPPROTO_UDP)) {
        denied = true;
    }
    emit_event(&info, IPPROTO_UDP, denied);
    return denied ? 0 : 1;
}

SEC("cgroup/sendmsg6")
int handle_sendmsg6(struct bpf_sock_addr *ctx) {
    __u32 port = ctx->user_port;
    __u32 ip6_0 = ctx->user_ip6[0];
    __u32 ip6_1 = ctx->user_ip6[1];
    __u32 ip6_2 = ctx->user_ip6[2];
    __u32 ip6_3 = ctx->user_ip6[3];

    struct ctx_info info = {};
    info.cgroup_id = bpf_get_current_cgroup_id();
    info.family = AF_INET6;
    info.dport = bpf_ntohs(port);
    __u32 *dst = (__u32 *)info.ipv6;
    dst[0] = ip6_0;
    dst[1] = ip6_1;
    dst[2] = ip6_2;
    dst[3] = ip6_3;

    bool denied = false;
    if (is_denied(&info, IPPROTO_UDP)) {
        denied = true;
    } else if (is_default_deny() && !allow(&info, IPPROTO_UDP)) {
        denied = true;
    }
    emit_event(&info, IPPROTO_UDP, denied);
    return denied ? 0 : 1;
}

char LICENSE[] SEC("license") = "Apache-2.0";
