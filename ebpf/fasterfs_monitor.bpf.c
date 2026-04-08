// SPDX-License-Identifier: GPL-2.0
// fasterfs_monitor.bpf.c — TC eBPF: monitor MinIO HTTP traffic on loopback,
// track chunk hotness, emit HOT_CHUNK events to userspace via ring buffer.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP        0x0800
#define IPPROTO_TCP     6
#define TC_ACT_OK       0
#define MINIO_PORT      9000
#define HOT_THRESHOLD   3

// Index into global_stats array
#define STAT_READS      0
#define STAT_HOT_EVENTS 1
#define STAT_TOTAL_LAT  2
#define STAT_BYTES      3

struct chunk_event {
    __u64 chunk_key;
    __u64 latency_ns;
    __u32 bytes;
    __u8  is_hot;
    __u8  pad[3];
};

// LRU hash: chunk_key → access count
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} chunk_hotness SEC(".maps");

// Hash: local_port (u32) → egress timestamp (ns)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} flow_timestamps SEC(".maps");

// Array: global stats [reads, hot_events, total_lat_ns, bytes]
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

// Ring buffer: HOT_CHUNK events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MB
} events SEC(".maps");

static __always_inline void stat_add(__u32 idx, __u64 val) {
    __u64 *p = bpf_map_lookup_elem(&global_stats, &idx);
    if (p) __sync_fetch_and_add(p, val);
}

// Egress: fired when Python client sends HTTP GET → MinIO :9000
SEC("tc/egress")
int fasterfs_egress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Loopback in TC context DOES have a synthetic Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    // IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // TCP header — ihl is in 32-bit words
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20) return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    // Only traffic destined for MinIO
    if (bpf_ntohs(tcp->dest) != MINIO_PORT) return TC_ACT_OK;

    // Record timestamp keyed by local (source) port
    __u32 local_port = bpf_ntohs(tcp->source);
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&flow_timestamps, &local_port, &ts, BPF_ANY);

    return TC_ACT_OK;
}

// Ingress: fired when MinIO response arrives back from :9000
SEC("tc/ingress")
int fasterfs_ingress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20) return TC_ACT_OK;
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    // Only responses FROM MinIO
    if (bpf_ntohs(tcp->source) != MINIO_PORT) return TC_ACT_OK;

    // Lookup start timestamp by local (destination) port
    __u32 local_port = bpf_ntohs(tcp->dest);
    __u64 *start_ts = bpf_map_lookup_elem(&flow_timestamps, &local_port);
    if (!start_ts) return TC_ACT_OK;

    __u64 now     = bpf_ktime_get_ns();
    __u64 latency = now - *start_ts;
    bpf_map_delete_elem(&flow_timestamps, &local_port);

    // Chunk key: use connection tuple (src_ip, dst_port)
    __u64 chunk_key = ((__u64)(bpf_ntohl(ip->saddr)) << 32) | local_port;

    // Increment access count
    __u64 *cnt = bpf_map_lookup_elem(&chunk_hotness, &chunk_key);
    __u64 new_cnt = cnt ? (*cnt + 1) : 1;
    bpf_map_update_elem(&chunk_hotness, &chunk_key, &new_cnt, BPF_ANY);

    // Update global stats
    stat_add(STAT_READS, 1);
    stat_add(STAT_TOTAL_LAT, latency);
    stat_add(STAT_BYTES, skb->len);

    // Emit HOT_CHUNK event when threshold crossed
    if (new_cnt > HOT_THRESHOLD) {
        struct chunk_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->chunk_key  = chunk_key;
            e->latency_ns = latency;
            e->bytes      = skb->len;
            e->is_hot     = 1;
            bpf_ringbuf_submit(e, 0);
        }
        stat_add(STAT_HOT_EVENTS, 1);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
