// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

#include "ptr_share.h"

char _license[] SEC("license") = "GPL";

//typedef char raw_ds[sizeof(struct ds)];

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, BPF_F_MMAPABLE);
    __type(key, __u32);
    __type(value, struct ds);
} data_map SEC(".maps");

int my_pid = 0;

SEC("raw_tracepoint/sys_enter")
int test_mmap(void *ctx)
{
    int zero = 0;
    struct ds *p;
    
    /* Only procced when syscall comes from the userspace prog */
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid)
        return 0;

    /* Accessing first element of the array */
    p = bpf_map_lookup_elem(&data_map, &zero);
    
    if (p) {
        bpf_printk("values at index %d is: %d\n", zero, p->x);
        bpf_printk("Pointer at index %d is: %lx\n", zero, p->next);

        /* verifier pukes */
        /*
        struct ds *q = (struct ds *)p->next;
        bpf_printk("val: %d\n", q->x);
        */

        struct ds *q = (struct ds *)bpf_ptr_promote(p->next);
        if (q)
          bpf_printk("val: %d\n", q->x);
    }

    return 0;
}

