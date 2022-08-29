#ifndef __PTR_SHARE_H__
#define __PTR_SHARE_H__

#include <inttypes.h>

//struct ds {
    //int x;
    //int delta;
    //struct ds *next;
//};

struct __attribute__((__packed__)) shared_region {
  void *userspace_base_addr;
  uint64_t region[1024]; // 1MB
};

#endif
