// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 4

#ifndef __packed
#define __packed __attribute__((packed))
#endif

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
	.max_entries = MAX_CPUS,
};

SEC("xdp_send")
int xdp_send_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (data < data_end) {
		/* The XDP perf_event_output handler will use the upper 32 bits
		 * of the flags argument as a number of bytes to include of the
		 * packet payload in the event data. If the size is too big, the
		 * call to bpf_perf_event_output will fail and return -EFAULT.
		 *
		 * See bpf_xdp_event_output in net/core/filter.c.
		 *
		 * The BPF_F_CURRENT_CPU flag means that the event output fd
		 * will be indexed by the CPU number in the event map.
		 */
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
