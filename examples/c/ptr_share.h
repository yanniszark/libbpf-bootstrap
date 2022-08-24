#ifndef __PTR_SHARE_H__
#define __PTR_SHARE_H__

#include <inttypes.h>

struct ds {
    int x;
    int delta;
    struct ds *next;
};

#endif
