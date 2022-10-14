// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "ptr_share.skel.h"

#include "ptr_share.h"

struct map_data {
    struct shared_region shared_region[1];
};

static size_t roundup_page(size_t sz)
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    return (sz + page_size - 1) / page_size * page_size;
}

int main(int argc, char *argv[])
{
    const size_t map_sz = roundup_page(sizeof(struct map_data));
    const int zero = 0;
    const long page_size = sysconf(_SC_PAGE_SIZE);
    int err, duration = 0, i, data_map_fd, data_map_id;
    struct bpf_map *data_map;
    void *map_mmaped = NULL;
    struct bpf_map_info map_info;
    __u32 map_info_sz = sizeof(map_info);
    struct map_data *map_data;
    struct ptr_share_bpf *skel;

    skel = ptr_share_bpf__open();
    if (!skel) {
        fprintf(stderr, "skel_open: skeleton open failed!\n");
        return;
    }

    /* at least 4 pages of data */
    err = bpf_map__set_max_entries(skel->maps.data_map, map_sz);

    if (err) {
        fprintf(stderr, "bpf_map__set_max_entries: failed!\n");
        goto cleanup;
    }

    /* ensure BPF program only handles syscalls from our process */
    skel->bss->my_pid = getpid();

    err = ptr_share_bpf__load(skel);
    if (err) {
        fprintf(stderr, "skel_load: skeleton load failed!\n");
        goto cleanup;
    }

    data_map = skel->maps.data_map;
    data_map_fd = bpf_map__fd(data_map);

    /* get map's ID */
    memset(&map_info, 0, map_info_sz);
    err = bpf_obj_get_info_by_fd(data_map_fd, &map_info, &map_info_sz);
    if (err) {
        fprintf(stderr, "map_get_info: failed %d\n", errno);
        goto cleanup;
    }
    data_map_id = map_info.id;

    /* map as R/W first */
    map_mmaped = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
              data_map_fd, 0);
    if (map_mmaped == MAP_FAILED) {
        fprintf(stderr, "data_mmap: data_map mmap failed %d\n", errno);
        map_mmaped = NULL;
        goto cleanup;
    }

    map_data = map_mmaped;

    map_data->shared_region[0].userspace_base_addr = (void *)(&map_data->shared_region[0]);
    printf("userspace base addr: %p\n", &map_data->shared_region[0]);
    printf("userspace base addr: %p\n", map_data->shared_region[0].userspace_base_addr);
    printf("void * size: %lu\n", sizeof(void *));

    struct test_struct* ptr_to_elem = &map_data->shared_region[0].region[16];
    ptr_to_elem->a = 1;
    ptr_to_elem->b = 2;
    ptr_to_elem->c = 3;

    printf("userspace pointer: %p\n", ptr_to_elem);
    printf("Data: %d %d %d\n", ptr_to_elem->a, ptr_to_elem->b, ptr_to_elem->c);

    uint64_t ptr_int = (uint64_t)ptr_to_elem;
    printf("userspace int pointer: %lx\n", ptr_int);
    uint64_t *ptr_to_ptr = &map_data->shared_region[0].region[4];
    *ptr_to_ptr = ptr_int;

    err = ptr_share_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach_raw_tp: failed %d\n", err);
        goto cleanup;
    }

    usleep(1);

    ptr_share_bpf__destroy(skel);
    skel = NULL;
    map_mmaped = NULL;

    /* map should be still held by active mmap */
    data_map_fd = bpf_map_get_fd_by_id(data_map_id);
    if (data_map_fd < 0) {
        fprintf(stderr, "get_map_by_id: failed %d\n", errno);
        munmap(map_mmaped, map_sz);
        goto cleanup;
    }
    close(data_map_fd);

    /* this should release data map finally */
    munmap(map_mmaped, map_sz);

    /* we need to wait for RCU grace period */
    for (i = 0; i < 10000; i++) {
        __u32 id = data_map_id - 1;
        if (bpf_map_get_next_id(id, &id) || id > data_map_id)
            break;
        usleep(1);
    }

cleanup:
    if (map_mmaped)
        munmap(map_mmaped, map_sz);
    ptr_share_bpf__destroy(skel);
}