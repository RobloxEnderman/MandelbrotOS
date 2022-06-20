#include <fb/fb.h>
#include <fs/vfs.h>
#include <lock.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <vec.h>

#define ALIGN_DOWN(__addr, __align) ((__addr) & ~((__align)-1))
#define ALIGN_UP(__addr, __align) (((__addr) + (__align)-1) & ~((__align)-1))

pagemap_t kernel_pagemap;

static inline uint64_t *vmm_get_next_level(uint64_t *table, size_t index) {
  void *ret = NULL;

  if (table[index] & 1)
    ret = (void *)(table[index] & ~((uintptr_t)0xfff));
  else {
    ret = pcalloc(1);
    table[index] = (uint64_t)ret | 0b111;
  }
  return ret + PHYS_MEM_OFFSET;
}

void vmm_invalidate_tlb(pagemap_t *pagemap, uintptr_t virtual_address) {
  uint64_t cr3;
  asm volatile("mov %%cr3, %0" : "=r"(cr3) : : "memory");
  if (cr3 == (uint64_t)pagemap->top_level)
    asm volatile("invlpg (%0)" : : "r"(virtual_address));
}

void vmm_map_page(pagemap_t *pagemap, uintptr_t physical_address,
                  uintptr_t virtual_address, uint64_t flags) {
  LOCK(pagemap->lock);

  size_t pml_entry4 = (size_t)(virtual_address & ((size_t)0x1ff << 39)) >> 39;
  size_t pml_entry3 = (size_t)(virtual_address & ((size_t)0x1ff << 30)) >> 30;
  size_t pml_entry2 = (size_t)(virtual_address & ((size_t)0x1ff << 21)) >> 21;
  size_t pml_entry1 = (size_t)(virtual_address & ((size_t)0x1ff << 12)) >> 12;

  uint64_t *pml3 = vmm_get_next_level(
    (void *)pagemap->top_level + PHYS_MEM_OFFSET, pml_entry4);
  uint64_t *pml2 = vmm_get_next_level(pml3, pml_entry3);
  uint64_t *pml1 = vmm_get_next_level(pml2, pml_entry2);

  /* *(uint64_t *)((uint64_t)pml1 + pml_entry1 * 8) = physical_address | flags;
   */
  pml1[pml_entry1] = physical_address | flags;

  vmm_invalidate_tlb(pagemap, virtual_address);

  UNLOCK(pagemap->lock);
}

void vmm_unmap_page(pagemap_t *pagemap, uintptr_t virtual_address) {
  LOCK(pagemap->lock);

  size_t pml_entry4 = (size_t)(virtual_address & ((size_t)0x1ff << 39)) >> 39;
  size_t pml_entry3 = (size_t)(virtual_address & ((size_t)0x1ff << 30)) >> 30;
  size_t pml_entry2 = (size_t)(virtual_address & ((size_t)0x1ff << 21)) >> 21;
  size_t pml_entry1 = (size_t)(virtual_address & ((size_t)0x1ff << 12)) >> 12;

  uint64_t *pml3 = vmm_get_next_level(
    (void *)pagemap->top_level + PHYS_MEM_OFFSET, pml_entry4);
  uint64_t *pml2 = vmm_get_next_level(pml3, pml_entry3);
  uint64_t *pml1 = vmm_get_next_level(pml2, pml_entry2);

  /* *(uint64_t *)((uint64_t)pml1 + pml_entry1 * 8) = 0; */
  pml1[pml_entry1] = 0;

  vmm_invalidate_tlb(pagemap, virtual_address);

  UNLOCK(pagemap->lock);
}

uintptr_t vmm_virt_to_phys(pagemap_t *pagemap, uintptr_t virtual_address) {
  size_t pml_entry4 = (size_t)(virtual_address & ((size_t)0x1ff << 39)) >> 39;
  size_t pml_entry3 = (size_t)(virtual_address & ((size_t)0x1ff << 30)) >> 30;
  size_t pml_entry2 = (size_t)(virtual_address & ((size_t)0x1ff << 21)) >> 21;
  size_t pml_entry1 = (size_t)(virtual_address & ((size_t)0x1ff << 12)) >> 12;

  uint64_t *pml3 = vmm_get_next_level(
    (void *)pagemap->top_level + PHYS_MEM_OFFSET, pml_entry4);
  uint64_t *pml2 = vmm_get_next_level(pml3, pml_entry3);
  uint64_t *pml1 = vmm_get_next_level(pml2, pml_entry2);

  if (!(pml1[pml_entry1] & 1))
    return 0;

  return (pml1[pml_entry1]) & ~((uintptr_t)0xfff);
}

uintptr_t vmm_get_kernel_address(pagemap_t *pagemap,
                                 uintptr_t virtual_address) {
  uintptr_t aligned_virtual_address = ALIGN_DOWN(virtual_address, PAGE_SIZE);
  uintptr_t phys_addr = vmm_virt_to_phys(pagemap, virtual_address);
  return (phys_addr + PHYS_MEM_OFFSET + virtual_address -
          aligned_virtual_address);
}

void vmm_memcpy(pagemap_t *pagemap_1, uintptr_t virtual_address_1,
                pagemap_t *pagemap_2, uintptr_t virtual_address_2,
                size_t count) {
  uintptr_t aligned_virtual_address_1 =
    ALIGN_DOWN(virtual_address_1, PAGE_SIZE);
  uintptr_t aligned_virtual_address_2 =
    ALIGN_DOWN(virtual_address_2, PAGE_SIZE);

  uint8_t *phys_addr_1 =
    (uint8_t *)vmm_virt_to_phys(pagemap_1, aligned_virtual_address_1);
  uint8_t *phys_addr_2 =
    (uint8_t *)vmm_virt_to_phys(pagemap_2, aligned_virtual_address_2);

  size_t align_difference_1 = virtual_address_1 - aligned_virtual_address_1;
  size_t align_difference_2 = virtual_address_2 - aligned_virtual_address_2;

  for (size_t i = 0; i < count; i++) {
    *(phys_addr_1 + PHYS_MEM_OFFSET + align_difference_1) =
      *(phys_addr_2 + PHYS_MEM_OFFSET + align_difference_2);

    if (!((++align_difference_1 + 1) % PAGE_SIZE)) {
      align_difference_1 = 0;

      virtual_address_1 += PAGE_SIZE;

      aligned_virtual_address_1 = ALIGN_DOWN(virtual_address_1, PAGE_SIZE);
      phys_addr_1 =
        (uint8_t *)vmm_virt_to_phys(pagemap_1, aligned_virtual_address_1);
    }

    if (!((++align_difference_2 + 1) % PAGE_SIZE)) {
      align_difference_2 = 0;

      virtual_address_2 += PAGE_SIZE;

      aligned_virtual_address_2 = ALIGN_DOWN(virtual_address_2, PAGE_SIZE);
      phys_addr_2 =
        (uint8_t *)vmm_virt_to_phys(pagemap_2, aligned_virtual_address_2);
    }
  }
}

void vmm_load_pagemap(pagemap_t *pagemap) {
  asm volatile("mov %0, %%cr3" : : "a"(pagemap->top_level));
}

pagemap_t *vmm_create_new_pagemap() {
  pagemap_t *new_map = kcalloc(sizeof(pagemap_t));
  new_map->top_level = pcalloc(1);

  uint64_t *kernel_top =
    (uint64_t *)((void *)kernel_pagemap.top_level + PHYS_MEM_OFFSET);
  uint64_t *user_top =
    (uint64_t *)((void *)new_map->top_level + PHYS_MEM_OFFSET);

  for (uintptr_t i = 256; i < 512; i++)
    user_top[i] = kernel_top[i];

  new_map->ranges.data = kcalloc(sizeof(mmap_range_t *));

  return new_map;
}

pagemap_t *vmm_fork_pagemap(pagemap_t *pg) {
  pagemap_t *new_pg = vmm_create_new_pagemap();

  for (size_t i = 0; i < (size_t)pg->ranges.length; i++) {
    mmap_range_t *range = pg->ranges.data[i];
    mmap_range_t *new_range = kmalloc(sizeof(mmap_range_t));

    if (range->flags & MAP_SHARED) {
      *new_range = *range;
      for (size_t j = 0; j < range->length; j += PAGE_SIZE)
        vmm_map_page(new_pg, range->phys_addr + j, range->virt_addr + j,
                     (range->prot & PROT_WRITE) ? 0b111 : 0b101);
    } else {
      if (range->flags & MAP_ANON) {
        uintptr_t mem = (uintptr_t)pcalloc(range->length / PAGE_SIZE);
        for (size_t j = 0; j < range->length; j += PAGE_SIZE)
          vmm_map_page(new_pg, (uintptr_t)mem + j, range->virt_addr + j,
                       (range->prot & PROT_WRITE) ? 0b111 : 0b101);
        *new_range = *range;
        new_range->phys_addr = mem;
        memcpy((void *)(mem + PHYS_MEM_OFFSET),
               (void *)(range->phys_addr + PHYS_MEM_OFFSET), range->length);
      } else {
        uintptr_t mem = (uintptr_t)vfs_mmap(
          range->file->file, new_pg, range->file, (void *)range->virt_addr,
          range->length, range->offset, range->flags, range->prot);
        *new_range = *range;
        new_range->phys_addr = mem;
      }
    }

    vec_push(&new_pg->ranges, new_range);
  }

  return new_pg;
}

void vmm_destroy_pagemap(pagemap_t *pagemap) {
  for (size_t i = 0; i < (size_t)pagemap->ranges.length; i++) {
    for (size_t j = 0; j < pagemap->ranges.data[i]->length; j += PAGE_SIZE)
      vmm_unmap_page(pagemap,
                     (uintptr_t)(pagemap->ranges.data[i]->virt_addr + j));
    if (pagemap->ranges.data[i]->flags & MAP_ANON)
      pmm_free_pages((void *)pagemap->ranges.data[i]->phys_addr,
                     pagemap->ranges.data[i]->length / PAGE_SIZE);
  }

  kfree(pagemap->ranges.data);
  pmm_free_pages((void *)pagemap->top_level, 1);
  kfree(pagemap);
}

void vmm_mmap_range(pagemap_t *pagemap, uintptr_t phys_addr,
                    uintptr_t virt_addr, size_t length, int flags, int prot) {
  for (size_t i = 0; i < length; i += PAGE_SIZE)
    vmm_map_page(pagemap, phys_addr + i, virt_addr + i,
                 (prot & PROT_WRITE) ? 0b111 : 0b101);

  mmap_range_t *mmap_range = kmalloc(sizeof(mmap_range_t));
  *mmap_range = (mmap_range_t){
    .file = NULL,
    .flags = flags | MAP_ANON,
    .length = length,
    .offset = 0,
    .prot = prot,
    .phys_addr = phys_addr,
    .virt_addr = virt_addr,
  };

  vec_push(&pagemap->ranges, mmap_range);
}

uintptr_t vmm_range_to_addr(pagemap_t *pagemap, uintptr_t virt_addr) {
  for (size_t i = 0; i < (size_t)pagemap->ranges.length; i++)
    if (pagemap->ranges.data[i]->virt_addr == virt_addr)
      return pagemap->ranges.data[i]->phys_addr;
  return 0;
}

int init_vmm() {
  kernel_pagemap.top_level = (uint64_t *)pcalloc(1);

  for (uint64_t i = 256; i < 512; i++)
    vmm_get_next_level(kernel_pagemap.top_level, i);

  for (uintptr_t i = PAGE_SIZE; i < 0x100000000; i += PAGE_SIZE) {
    vmm_map_page(&kernel_pagemap, i, i, 0b11);
    vmm_map_page(&kernel_pagemap, i, i + PHYS_MEM_OFFSET, 0b11);
  }

  for (uintptr_t i = 0; i < 0x80000000; i += PAGE_SIZE)
    vmm_map_page(&kernel_pagemap, i, i + KERNEL_MEM_OFFSET, 0b111);

  vmm_load_pagemap(&kernel_pagemap);

  return 0;
}
