// SPDX-License-Identifier: GPL-2.0
// fasterfs_sockopts.bpf.c — SOCK_OPS: auto-set TCP_NODELAY + TCP_QUICKACK
// on every TCP connection to MinIO port 9000. Removes Nagle's 40ms delay.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MINIO_PORT   9000
#define IPPROTO_TCP  6
#define TCP_NODELAY  1
#define TCP_QUICKACK 12

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} sockops_stats SEC(".maps");

#define STAT_TUNED    0
#define STAT_NODELAY  1
#define STAT_QUICKACK 2

static __always_inline void stat_inc(__u32 idx) {
    __u64 *p = bpf_map_lookup_elem(&sockops_stats, &idx);
    if (p) __sync_fetch_and_add(p, 1);
}

SEC("sockops")
int fasterfs_sockops(struct bpf_sock_ops *skops) {
    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
        return 1;

    // remote_port is in network byte order in the upper 16 bits
    __u16 rport = bpf_ntohs((__u16)(skops->remote_port >> 16));
    if (rport != MINIO_PORT)
        return 1;

    // Enable state transition callbacks
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

    int one = 1;

    // Disable Nagle's algorithm
    int r1 = bpf_setsockopt(skops, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (r1 == 0) stat_inc(STAT_NODELAY);

    // Disable delayed ACKs
    int r2 = bpf_setsockopt(skops, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
    if (r2 == 0) stat_inc(STAT_QUICKACK);

    stat_inc(STAT_TUNED);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
