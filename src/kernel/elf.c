#include <elf.h>
#include <fb/fb.h>
#include <fs/vfs.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <tasking/scheduler.h>

#define ELF_RELOCATEABLE 1
#define ELF_EXECUTABLE 2

#define ELF_HEAD_LOAD 1

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define ROUND_UP(A, B)                                                         \
  ({                                                                           \
    typeof(A) _a_ = A;                                                         \
    typeof(B) _b_ = B;                                                         \
    (_a_ + (_b_ - 1)) / _b_;                                                   \
  })

char elf_ident[4] = {0x7f, 'E', 'L', 'F'};

uint8_t elf_run_binary(char *path, pagemap_t *pagemap, uintptr_t *entry) {
  fs_file_t *file = vfs_open(path);
  uint8_t *buffer = kcalloc(file->length);
  vfs_read(file, buffer, 0, file->length);

  elf_header_t *header = (elf_header_t *)buffer;
  if (header->type != ELF_EXECUTABLE)
    return 1;
  if (memcmp((void *)header->identifier, elf_ident, 4))
    return 1;

  elf_header_t *elf_header = (elf_header_t *)buffer;
  elf_prog_header_t *prog_header = (void *)(buffer + elf_header->prog_head_off);

  for (size_t i = 0; i < elf_header->prog_head_count; i++) {
    if (prog_header[i].type == ELF_HEAD_LOAD) {
      size_t misalign = prog_header[i].phys_addr & (PAGE_SIZE - 1);
      void *mem =
        pcalloc(ROUND_UP(misalign + prog_header[i].mem_size, PAGE_SIZE));
      vmm_mmap_range(
        pagemap, (uintptr_t)mem, prog_header[i].virt_addr,
        ROUND_UP(misalign + prog_header[i].mem_size, PAGE_SIZE) * PAGE_SIZE,
        MAP_ANON | MAP_PRIVATE,
        PROT_READ | PROT_EXEC | ((prog_header->flags & PF_W) ? PROT_WRITE : 0));
      memcpy((void *)(((uintptr_t)mem + PHYS_MEM_OFFSET + misalign)),
             (void *)((uintptr_t)buffer + prog_header[i].offset),
             prog_header[i].file_size);
    }
  }

  if (entry)
    *entry = elf_header->entry;

  return 0;
}
