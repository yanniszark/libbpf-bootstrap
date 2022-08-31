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
    __type(value, struct shared_region);
} data_map SEC(".maps");

int my_pid = 0;

inline void *ptr_promote(void *userspace_base_addr, void *kernel_base_addr, uint64_t userspace_ptr) {
  uint64_t delta = userspace_ptr - (uint64_t)userspace_base_addr;

  if (delta >= sizeof(struct shared_region)) {
    return kernel_base_addr;
  }
  
  return kernel_base_addr + delta;
}

SEC("raw_tracepoint/sys_enter")
int test_mmap(void *ctx)
{
    int zero = 0;
    struct shared_region *shared_region;
    
    /* Only procced when syscall comes from the userspace prog */
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != my_pid)
        return 0;

    /* Accessing first element of the array */
    shared_region = bpf_map_lookup_elem(&data_map, &zero);
    
    if (shared_region) {
        bpf_printk("userspace base address: %px\n", shared_region->userspace_base_addr);
        bpf_printk("kernel base address: %px\n", shared_region);
        bpf_printk("userspace address: %lx\n", shared_region->region[0]);
        bpf_printk("kernel address: %px\n", &shared_region->region[2]);

        void *elem = ptr_promote(shared_region->userspace_base_addr, shared_region, shared_region->region[0]);
        bpf_printk("kernel address ptr_promote: %px\n", elem);
        char *data = (char *)elem;

        if (!data && data >= shared_region + sizeof(struct shared_region))
          return 0;
        
        bpf_printk("value: %d\n", *data);
    }
    
    bpf_printk("void * size: %lu\n", sizeof(void *));

    return 0;
}

