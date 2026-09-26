#define KBUILD_MODNAME "bor_box"

// Silence Ubuntu 20.04 Clang macro collision warnings
#undef __HAVE_BUILTIN_BSWAP16__
#undef __HAVE_BUILTIN_BSWAP32__
#undef __HAVE_BUILTIN_BSWAP64__

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

BPF_PERF_OUTPUT(events);

struct packet_meta {
    u32 len;
};

struct dns_hdr {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
} __attribute__((packed));

int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Loop Bypass: Check for the Magic MAC (00:DE:AD:BE:EF:00)
    if (eth->h_source[0] == 0x00 && eth->h_source[1] == 0xDE &&
        eth->h_source[2] == 0xAD && eth->h_source[3] == 0xBE &&
        eth->h_source[4] == 0xEF && eth->h_source[5] == 0x00) {
        return XDP_PASS; 
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    if (ip->ihl < 5) return XDP_PASS;
        
    u8 *ip_end = (u8 *)ip + (ip->ihl * 4);
    if ((void *)ip_end > data_end) return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)ip_end;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53)) return XDP_PASS;

    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end) return XDP_PASS;

    // 1. Unpack all 6 DNS header fields to host byte order
    u16 id      = bpf_ntohs(dns->id);
    u16 flags   = bpf_ntohs(dns->flags);
    u16 qdcount = bpf_ntohs(dns->qdcount);
    u16 ancount = bpf_ntohs(dns->ancount);
    u16 nscount = bpf_ntohs(dns->nscount);
    u16 arcount = bpf_ntohs(dns->arcount);

    // 2. Extract standard DNS subflags from the flags field
    u16 qr     = (flags >> 15) & 0x01;
    u16 opcode = (flags >> 11) & 0x0F;
    u16 aa     = (flags >> 10) & 0x01;
    u16 tc     = (flags >> 9)  & 0x01;
    u16 rd     = (flags >> 8)  & 0x01;
    u16 ra     = (flags >> 7)  & 0x01;
    u16 rcode  = flags & 0x0F;

    // 3. User-defined rules evaluated here (First-match wins)
    /* %RULES_CODE% */

    // Default Action: ALLOW
    return XDP_PASS;

limit_packet: {
        u32 pkt_len = data_end - data;
        if (pkt_len > 256) {
            pkt_len = 256;
        }

        struct packet_meta meta = {};
        meta.len = pkt_len;

        events.perf_submit_skb(ctx, pkt_len, &meta, sizeof(meta));
        return XDP_DROP;
    }
}
