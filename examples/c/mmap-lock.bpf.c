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
    int zero = 0, one = 1, two = 2, three = 3, four = 4;
	__u64 val, *lock, *x, *y, *user_count, *kern_count;
	
    /* Only procced when syscall comes from the userspace prog */
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid)
        return 0;

	lock = bpf_map_lookup_elem(&data_map, &zero);
	
    x = bpf_map_lookup_elem(&data_map, &one);
	y = bpf_map_lookup_elem(&data_map, &two);
	
    user_count = bpf_map_lookup_elem(&data_map, &three);
	kern_count = bpf_map_lookup_elem(&data_map, &four);
	
    if (!__sync_bool_compare_and_swap(lock, 0, 1)) {
        return 0;
    }
    else {
        (*x)++;     
        (*y)++;     
        if (*x != *y)
            bpf_printk("data race!\n");
        (*kern_count)++;
        __sync_fetch_and_add(lock, 1);
    }

	return 0;
}

