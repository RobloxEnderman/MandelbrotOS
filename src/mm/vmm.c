#include <lock.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ALIGN_DOWN(__addr, __align) ((__addr) & ~((__align)-1))

static volatile lock_t vmm_lock = {0};
pagemap_t kernel_pagemap;

static uint64_t *get_next_level(uint64_t *table, size_t index, uint64_t flags) {
  uint64_t *ret = 0;
  uint64_t *entry = (void *)((uint64_t)table + PHYS_MEM_OFFSET) + index * 8;

  if ((entry[0] & 1) != 0)
    ret = (uint64_t *)(entry[0] & (uint64_t)~0xfff);
  else {
    ret = pmalloc(1);
    entry[0] = (uint64_t)ret | flags;
  }

  return ret;
}

void invalidate_tlb(pagemap_t *pagemap, uintptr_t virtual_address) {
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

  uint64_t *pml3 = get_next_level(pagemap->top_level, pml_entry4, flags);
  uint64_t *pml2 = get_next_level(pml3, pml_entry3, flags);
  uint64_t *pml1 = get_next_level(pml2, pml_entry2, flags);

  *(uint64_t *)((uint64_t)pml1 + PHYS_MEM_OFFSET + pml_entry1 * 8) =
      physical_address | flags;

  invalidate_tlb(pagemap, virtual_address);

  UNLOCK(pagemap->lock);
}

void vmm_unmap_page(pagemap_t *pagemap, uintptr_t virtual_address) {
  LOCK(pagemap->lock);

  size_t pml_entry4 = (size_t)(virtual_address & ((size_t)0x1ff << 39)) >> 39;
  size_t pml_entry3 = (size_t)(virtual_address & ((size_t)0x1ff << 30)) >> 30;
  size_t pml_entry2 = (size_t)(virtual_address & ((size_t)0x1ff << 21)) >> 21;
  size_t pml_entry1 = (size_t)(virtual_address & ((size_t)0x1ff << 12)) >> 12;

  uint64_t *pml3 = get_next_level(pagemap->top_level, pml_entry4, 0b111);
  uint64_t *pml2 = get_next_level(pml3, pml_entry3, 0b111);
  uint64_t *pml1 = get_next_level(pml2, pml_entry2, 0b111);

  *(uint64_t *)((uint64_t)pml1 + PHYS_MEM_OFFSET + pml_entry1 * 8) = 0;

  invalidate_tlb(pagemap, virtual_address);

  UNLOCK(pagemap->lock);
}

uintptr_t vmm_virt_to_phys(pagemap_t *pagemap, uintptr_t virtual_address) {
  size_t pml_entry4 = (size_t)(virtual_address & ((size_t)0x1ff << 39)) >> 39;
  size_t pml_entry3 = (size_t)(virtual_address & ((size_t)0x1ff << 30)) >> 30;
  size_t pml_entry2 = (size_t)(virtual_address & ((size_t)0x1ff << 21)) >> 21;
  size_t pml_entry1 = (size_t)(virtual_address & ((size_t)0x1ff << 12)) >> 12;

  uint64_t *pml3 = get_next_level(pagemap->top_level, pml_entry4, 0b111);
  uint64_t *pml2 = get_next_level(pml3, pml_entry3, 0b111);
  uint64_t *pml1 = get_next_level(pml2, pml_entry2, 0b111);

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

pagemap_t *create_new_pagemap() {
  pagemap_t *new_map = kcalloc(sizeof(pagemap_t));
  new_map->top_level = pcalloc(1);

  uint64_t *kernel_top =
      (uint64_t *)((void *)kernel_pagemap.top_level + PHYS_MEM_OFFSET);
  uint64_t *user_top =
      (uint64_t *)((void *)new_map->top_level + PHYS_MEM_OFFSET);

  for (uintptr_t i = 256; i < 512; i++)
    user_top[i] = kernel_top[i];

  return new_map;
}

int init_vmm() {
  kernel_pagemap.top_level = (uint64_t *)pcalloc(1);

  for (uint64_t i = 256; i < 512; i++)
    get_next_level(kernel_pagemap.top_level, i, 0b111);

  for (uintptr_t i = PAGE_SIZE; i < 0x100000000; i += PAGE_SIZE) {
    vmm_map_page(&kernel_pagemap, i, i, 0b111);
    vmm_map_page(&kernel_pagemap, i, i + PHYS_MEM_OFFSET, 0b111);
  }

  for (uintptr_t i = 0; i < 0x80000000; i += PAGE_SIZE)
    vmm_map_page(&kernel_pagemap, i, i + KERNEL_MEM_OFFSET, 0b111);

  vmm_load_pagemap(&kernel_pagemap);

  return 0;
}
