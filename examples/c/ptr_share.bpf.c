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

// #define ptr_translate(userspace_base_addr, kernel_base_addr, userspace_ptr)       \
//     do {                                                                          \
//         uint64_t delta = (uint64_t)userspace_ptr - (uint64_t)userspace_base_addr; \
//         if (delta >= sizeof(struct shared_region)) {                              \
//             return -1;                                                            \
//         }                                                                         \
//         if


inline void *ptr_translate(
    void *userspace_base_addr,
    void *kernel_base_addr,
    uint64_t userspace_ptr,
    uint64_t struct_size) {
  uint64_t delta = userspace_ptr - (uint64_t)userspace_base_addr;

  if (delta >= sizeof(struct shared_region)) {
    return NULL;
  }

  void* kernel_ptr = kernel_base_addr + delta;
  if (struct_size > sizeof(struct shared_region)) {
    return NULL;
  }
  if (kernel_ptr >= ((uint64_t) kernel_base_addr) + sizeof(struct shared_region) - struct_size) {
    return NULL;
  }
  return kernel_ptr;
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

        // In the userspace program, we put:
        // - The userspace pointer in the 4th byte of the array.
        // - The actual struct in the 16th byte of the array.
        bpf_printk("userspace pointer: %lx\n", * (uint64_t *) &shared_region->region[4]);
        bpf_printk("kernel pointer: %px\n", (uint64_t *) &shared_region->region[16]);

        void *elem = ptr_translate(shared_region->userspace_base_addr,
                                   shared_region,
                                   * (uint64_t *) &shared_region->region[4],
                                   sizeof(struct test_struct));
        if (elem == NULL) {
            return -1;
        }
        // bpf_printk("kernel address ptr_translate: %px\n", elem);
        // struct test_struct *data = (struct test_struct *) elem;

        // void * shared_region_end = shared_region + 1;
        // bpf_printk("Shared region start address: '%lx' and end address '%lx'\n", shared_region, shared_region_end);

        // if (data < shared_region)
        //     return 0;
        // if (data >= shared_region_end - sizeof(struct test_struct))
        //     return 0;
        bpf_printk("value: %d\n", ((struct test_struct*) elem)->a);
    }
    return 0;
}
