#ifndef CFS_H
#define CFS_H

#define MAX_HIT_COUNT 6

bool cf_initialized=false;
GHashTable* cf_map;
GHashTable* meminfo_map;

typedef struct
{
    uint64_t src;
    unsigned char hitcount;
} SrcEdge;

typedef struct
{
    addr_t oracle_paddr;
    addr_t target_paddr;
    uint8_t backup;
} MemInfo;

#endif
