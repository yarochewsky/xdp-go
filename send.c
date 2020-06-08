#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "parsing.h"
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/perf_event.h>

#define SAMPLE_SIZE 1024ul

#ifndef __packed
#define __packed __attribute__((packed))
#endif


#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})



#define min(x, y) ((x) < (y) ? (x) : (y))


/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
} __packed;

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 0,
};


SEC("xdp/send")
int xdp_send_prog(struct xdp_md* ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

  if (data < data_end) {

		__u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size;
		struct S metadata;

		metadata.cookie = 0xdead;
		metadata.pkt_len = (__u16)(data_end - data);
		sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

		flags |= (__u64) sample_size << 32;

		bpf_perf_event_output(ctx, &my_map, flags, &metadata, sizeof(metadata));
  }
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
