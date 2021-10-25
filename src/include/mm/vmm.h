#ifndef __VMM_H__
#define __VMM_H__

#include <lock.h>
#include <stdint.h>

#define KERNEL_MEM_OFFSET 0xffffffff80000000

typedef struct pagemap {
  lock_t lock;
  uint64_t *top_level;
} pagemap_t;

extern pagemap_t kernel_pagemap;

void vmm_switch_map_to_kern();
void vmm_load_pagemap(pagemap_t *pagemap);
pagemap_t *create_new_pagemap();
int init_vmm();

#endif
