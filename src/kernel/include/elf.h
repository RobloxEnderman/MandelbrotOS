#ifndef __ELF_H__
#define __ELF_H__

#include <stdint.h>
#include <tasking/scheduler.h>

typedef struct elf_header {
  uint8_t identifier[16];

  uint16_t type;
  uint16_t machine;
  uint32_t version;

  uint64_t entry;

  uint64_t prog_head_off;
  uint64_t sect_head_off;

  uint32_t flags;

  uint16_t head_size;
  uint16_t prog_head_size;
  uint16_t prog_head_count;

  uint16_t sect_head_size;
  uint16_t sect_head_count;
  uint16_t sect_string_table;
} __attribute__((packed)) elf_header_t;

typedef struct elf_sect_header {
  uint32_t name;
  uint32_t type;
  uint64_t flags;
  uint64_t addr;
  uint64_t offset;
  uint64_t size;
  uint32_t link;
  uint32_t info;
  uint64_t addr_align;
  uint64_t entry_size;
} elf_sect_header_t;

typedef struct elf_prog_header {
  uint32_t type;
  uint32_t flags;

  uint64_t offset;
  uint64_t virt_addr;
  uint64_t phys_addr;
  uint64_t file_size;
  uint64_t mem_size;

  uint64_t reserved1;
} __attribute__((packed)) elf_prog_header_t;

int elf_load_binary(char *path, pagemap_t *pagemap, uintptr_t *entry);

#endif
