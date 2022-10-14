#ifndef __PTR_SHARE_H__
#define __PTR_SHARE_H__

#include <inttypes.h>

struct __attribute__((__packed__)) shared_region {
  uint8_t region[1024]; // 1KB
  void *userspace_base_addr;
};

struct test_struct {
  int a;
  int b;
  int c;
};

#endif