// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <errno.h>
#include "mmap_lock.skel.h"

struct map_data {
	__u64 val[512 * 4];
};

static size_t roundup_page(size_t sz)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	return (sz + page_size - 1) / page_size * page_size;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char *argv[])
{
	const size_t map_sz = roundup_page(sizeof(struct map_data));
	const int zero = 0;
	const long page_size = sysconf(_SC_PAGE_SIZE);
	int i, err, data_map_fd, data_map_id;
	struct bpf_map *data_map;
	void *map_mmaped = NULL;
	struct bpf_map_info map_info;
	__u32 map_info_sz = sizeof(map_info);
	struct map_data *map_data;
	struct mmap_lock_bpf *skel;
    
    atomic_uintmax_t *lock;
	__u64 *x, *y, *user_count, *kern_count;

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = mmap_lock_bpf__open();
    if (!skel) {
        fprintf(stderr, "skel_open: skeleton open failed!\n");
        return;
    }

	/* at least 4 pages of data */
	err = bpf_map__set_max_entries(skel->maps.data_map,
				       4 * (page_size / sizeof(__u64)));

    if (err) {
        fprintf(stderr, "bpf_map__set_max_entries: failed!\n"); 
        goto cleanup;
    }
	
    /* ensure BPF program only handles syscalls from our process */
	skel->bss->my_pid = getpid();

	err = mmap_lock_bpf__load(skel);
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

	/* map as R/W */
	map_mmaped = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
			  data_map_fd, 0);
    if (map_mmaped == MAP_FAILED) {
        fprintf(stderr, "data_mmap: data_map mmap failed %d\n", errno); 
        map_mmaped = NULL;
        goto cleanup;
    }
	
	map_data = map_mmaped;

	err = mmap_lock_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach_raw_tp: failed %d\n", err); 
        goto cleanup;
    }

    /* Implement all synchronization */
    lock = map_data->val;
    x = map_data->val + 1;
    y = map_data->val + 2;
    user_count = map_data->val + 3;
    kern_count = map_data->val + 4;

    uintmax_t expected = 0;
    
    while (!exiting) {
        while (!atomic_compare_exchange_strong(lock, &expected, 1))
            expected = 0;
        
        (*x)++;
        (*y)++;
        
        if (*x != *y) {
            printf("data race!\n");
            break;
        }

        (*user_count)++;
        atomic_store(lock, 0);
    }


	mmap_lock_bpf__destroy(skel);
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
	mmap_lock_bpf__destroy(skel);
}
