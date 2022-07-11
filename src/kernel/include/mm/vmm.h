#ifndef __VMM_H__
#define __VMM_H__

#include <lock.h>
#include <stddef.h>
#include <stdint.h>
#include <vec.h>

#define KERNEL_MEM_OFFSET 0xffffffff80000000

typedef struct syscall_file syscall_file_t; // Recursive inclusion
struct pagemap;

typedef struct mmap_range {
  syscall_file_t *file;
  uintptr_t phys_addr;
  uintptr_t virt_addr;
  size_t offset;
  size_t length;
  int flags;
  int prot;
} mmap_range_t;

typedef struct pagemap {
  lock_t lock;
  uint64_t *top_level;
  vec_t(mmap_range_t *) ranges;
} pagemap_t;

extern pagemap_t kernel_pagemap;

void vmm_load_pagemap(pagemap_t *pagemap);
pagemap_t *vmm_create_new_pagemap();
pagemap_t *vmm_fork_pagemap(pagemap_t *pg);
void vmm_map_page(pagemap_t *pagemap, uintptr_t physical_address,
                  uintptr_t virtual_address, uint64_t flags);
void vmm_unmap_page(pagemap_t *pagemap, uintptr_t virtual_address);
uintptr_t vmm_virt_to_phys(pagemap_t *pagemap, uintptr_t virtual_address);
uintptr_t vmm_get_kernel_address(pagemap_t *pagemap, uintptr_t virtual_address);
void vmm_destroy_pagemap(pagemap_t *pagemap);
void vmm_mmap_range(pagemap_t *pagemap, uintptr_t phys_addr,
                    uintptr_t virt_addr, size_t length, int flags, int prot);
uintptr_t vmm_range_to_addr(pagemap_t *pagemap, uintptr_t virt_addr);
int init_vmm();

#endif
