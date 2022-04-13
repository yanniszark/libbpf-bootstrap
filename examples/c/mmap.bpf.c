// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
} data_map SEC(".maps");

int my_pid = 0;

SEC("raw_tracepoint/sys_enter")
int test_mmap(void *ctx)
{
    int zero = 0;
	__u64 val, *p;
	
    /* Only procced when syscall comes from the userspace prog */
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid)
        return 0;

	/* data_map[0] = data_map[0] * 2; */
	p = bpf_map_lookup_elem(&data_map, &zero);
	
    if (p) {
        bpf_printk("val at index %d is: %u", zero, *p);
		val = (*p) * 2;
		bpf_map_update_elem(&data_map, &zero, &val, 0);
	}

	return 0;
}

