#include <cpu_locals.h>
#include <dev/device.h>
#include <drivers/ahci.h>
#include <drivers/apic.h>
#include <drivers/rtc.h>
#include <elf.h>
#include <errno.h>
#include <fb/fb.h>
#include <fs/vfs.h>
#include <lock.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <printf.h>
#include <registers.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/gdt.h>
#include <sys/idt.h>
#include <sys/syscall.h>
#include <tasking/scheduler.h>
#include <vec.h>

#define ALIGN_UP(__addr, __align) (((__addr) + (__align)-1) & ~((__align)-1))

#define CURRENT_PAGEMAP get_locals()->current_thread->parent->pagemap
#define CURRENT_PROC get_locals()->current_thread->parent
#define CURRENT_THREAD get_locals()->current_thread

#define MAX_HEAP_SIZE 0x10000

extern void syscall_isr();

int init_syscalls() {
  idt_set_gate(&idt[0x45], 1, 1, syscall_isr);
  return 0;
}

size_t syscall_open(char *path, int flags, int mode) {
  fs_file_t *file = vfs_open((char *)path);

  if (!file) {
    if (!(flags & O_CREAT))
      return (size_t)-ENOENT;

    char *str = strdup(path);
    for (ssize_t i = strlen(str) - 1; i >= 0; i--)
      if (str[i] == '/') {
        str[i] = 0;
        break;
      }

    fs_file_t *parent = vfs_open(str);

    kfree(str);

    if (!parent)
      return -ENOENT;

    if (flags & O_RDONLY &&
        vfs_check_can_read(parent, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
      return -EACCES;
    else if (flags & O_WRONLY &&
             vfs_check_can_write(parent, CURRENT_THREAD->uid,
                                 CURRENT_THREAD->gid))
      return -EACCES;
    else if (flags & O_RDWR && (vfs_check_can_read(parent, CURRENT_THREAD->uid,
                                                   CURRENT_THREAD->gid) ||
                                vfs_check_can_write(parent, CURRENT_THREAD->uid,
                                                    CURRENT_THREAD->gid)))
      return -EACCES;

    if (flags & O_EXEC &&
        vfs_check_can_exec(parent, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
      return -EACCES;

    vfs_close(parent);

    file = vfs_create(path, mode, CURRENT_THREAD->uid, CURRENT_THREAD->gid);
  }

  if (flags & O_RDONLY &&
      vfs_check_can_read(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
    return -EACCES;
  else if (flags & O_WRONLY &&
           vfs_check_can_write(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
    return -EACCES;
  else if (flags & O_RDWR && (vfs_check_can_read(file, CURRENT_THREAD->uid,
                                                 CURRENT_THREAD->gid) ||
                              vfs_check_can_write(file, CURRENT_THREAD->uid,
                                                  CURRENT_THREAD->gid)))
    return -EACCES;

  if (flags & O_EXEC &&
      vfs_check_can_exec(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
    return -EACCES;

  syscall_file_t *sfile = kmalloc(sizeof(syscall_file_t));
  *sfile = (syscall_file_t){
    .file = file,
    .flags = flags,
  };

  sfile->file->offset = 0;

  size_t i;
  for (i = 0; i < FDS_COUNT; i++)
    if (!CURRENT_PROC->fds[i]) {
      CURRENT_PROC->fds[i] = sfile;
      break;
    }

  if (i == FDS_COUNT) {
    vfs_close(file);
    kfree(sfile);
    return -EMFILE;
  }

  return i;
}

int syscall_close(size_t id) {
  syscall_file_t *file = CURRENT_PROC->fds[id];
  if (!file)
    return -EBADF;
  vfs_close(file->file);
  kfree(file);
  CURRENT_PROC->fds[id] = NULL;
  return 0;
}

ssize_t syscall_read(size_t id, uint8_t *buffer, size_t size) {
  syscall_file_t *file = CURRENT_PROC->fds[id];
  if (!file)
    return -EBADF;
  if (!(file->flags & (O_RDONLY | O_RDWR)))
    return -EINVAL;
  if (!size)
    return 0;

  if (size + file->file->offset > file->file->length && !ISDEV(file->file) &&
      !ISFIFO(file->file))
    size = file->file->length - file->file->offset;

  ssize_t read = vfs_read(file->file, buffer, file->file->offset, size);

  file->file->offset += size;

  return read;
}

ssize_t syscall_write(size_t id, uint8_t *buffer, size_t size) {
  syscall_file_t *file = CURRENT_PROC->fds[id];
  if (!file)
    return 0;
  if (!(file->flags & (O_WRONLY | O_RDWR)))
    return 0;
  if (!size)
    return 0;

  if (size + file->file->offset > file->file->length && !ISDEV(file->file) &&
      !ISFIFO(file->file))
    size = file->file->length - file->file->offset;

  ssize_t read = vfs_write(file->file, buffer, file->file->offset, size);

  file->file->offset += size;

  return read;
}

int syscall_execve(char *path, char **argv, char **env) {
  fs_file_t *file = vfs_open((char *)path);
  if (!file)
    return -ENOENT;
  if (vfs_check_can_read(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid) ||
      vfs_check_can_exec(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid)) {
    vfs_close(file);
    return -EACCES;
  }
  vfs_close(file);
  return sched_run_program(path, argv, env, "/dev/tty0", "/dev/tty0",
                           "/dev/tty0", 1);
}

void *syscall_mmap(mmap_args_t *args) {
  if (args->fd > -1) {
    if (args->fd >= FDS_COUNT || !CURRENT_PROC->fds[args->fd])
      return (void *)-EBADF;
    if (!(CURRENT_PROC->fds[args->fd]->flags & (O_RDONLY | O_RDWR)))
      return (void *)-EACCES;
  }
  if (!args->length)
    return (void *)-EINVAL;
  if (!(args->flags & MAP_SHARED) && !(args->flags & MAP_PRIVATE))
    return (void *)-EINVAL;

  uintptr_t addr;
  size_t needed_pages = ALIGN_UP(args->length, PAGE_SIZE) / PAGE_SIZE;

  CURRENT_PROC->mmaped_len += needed_pages * PAGE_SIZE;
  if (CURRENT_PROC->mmaped_len > MMAP_MAX_SIZE) {
    CURRENT_PROC->mmaped_len -= needed_pages * PAGE_SIZE;
    return (void *)-EMFILE;
  }

  if (args->flags & MAP_FIXED) {
    if ((uintptr_t)args->addr % PAGE_SIZE)
      return (void *)-EINVAL;
    addr = (uintptr_t)args->addr;
  } else {
    addr = CURRENT_PROC->mmap_top;
    CURRENT_PROC->mmap_top += ((needed_pages + 1) * PAGE_SIZE);
  }

  if (args->flags & MAP_ANON) {
    uintptr_t given_pages = (uintptr_t)pcalloc(needed_pages);
    if (!given_pages)
      return (void *)-ENOMEM;

    vmm_mmap_range(CURRENT_PAGEMAP, given_pages, addr, needed_pages * PAGE_SIZE,
                   args->flags, args->prot);
  } else {
    if (args->fd < 0)
      return (void *)-EBADF;

    syscall_file_t *file = CURRENT_PROC->fds[args->fd];

    if (args->prot & PROT_WRITE && args->flags & MAP_SHARED &&
        !(file->flags & (O_RDWR | O_WRONLY)))
      return (void *)-EACCES;
    if (ISFIFO(file->file))
      return (void *)-ENODEV;

    size_t len = args->length;
    size_t off = args->offset;
    size_t prt = args->prot;
    size_t flg = args->flags;

    vmm_load_pagemap(&kernel_pagemap);
    (void)vfs_mmap(file->file, CURRENT_PAGEMAP, file, (void *)addr, len, off,
                   prt, flg);
    vmm_load_pagemap(CURRENT_PAGEMAP);
  }

  return (void *)addr;
}

int syscall_munmap(void *addr, size_t length) {
  for (size_t i = 0; i < (size_t)CURRENT_PAGEMAP->ranges.length; i++) {
    if ((void *)CURRENT_PAGEMAP->ranges.data[i]->virt_addr == addr) {
      vec_remove(&CURRENT_PAGEMAP->ranges, CURRENT_PAGEMAP->ranges.data[i]);
      for (size_t i = 0; i < length; i += PAGE_SIZE)
        vmm_unmap_page(CURRENT_PAGEMAP, (uintptr_t)(addr + i));
      if (CURRENT_PAGEMAP->ranges.data[i]->flags & MAP_ANON)
        pmm_free_pages((void *)CURRENT_PAGEMAP->ranges.data[i]->phys_addr,
                       CURRENT_PAGEMAP->ranges.data[i]->length / PAGE_SIZE);
      return 0;
    }
  }
  return 1;
}

int syscall_stat(char *path, stat_t *stat) {
  fs_file_t *file = vfs_open(path);
  if (!file)
    return -ENOENT;
  if (vfs_check_can_read(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
    return -EACCES;
  vfs_fstat(file, stat);
  vfs_close(file);
  return 0;
}

int syscall_fstat(size_t id, stat_t *stat) {
  syscall_file_t *file = CURRENT_PROC->fds[id];
  if (!file)
    return -EBADF;
  if (vfs_check_can_read(file->file, CURRENT_THREAD->uid, CURRENT_THREAD->gid))
    return -EACCES;
  vfs_fstat(file->file, stat);
  return 0;
}

size_t syscall_getpid() { return CURRENT_PROC->pid; }

size_t syscall_getppid() {
  return (CURRENT_PROC->parent) ? CURRENT_PROC->parent->pid : (size_t)-1;
}

void syscall_exit(int code) { sched_exit(code, 0); }

size_t syscall_fork(registers_t *regs) {
  vmm_load_pagemap(&kernel_pagemap);
  size_t ret = sched_fork(regs);
  vmm_load_pagemap(CURRENT_PAGEMAP);
  return ret;
}

void syscall_gettimeofday(posix_time_t *time) {
  *time = rtc_mktime(rtc_get_datetime());
}

int syscall_fsync(size_t id) {
  syscall_file_t *file = CURRENT_PROC->fds[id];
  if (!file)
    return -EBADF;
  if (ISFIFO(file->file))
    return -EINVAL;
  return 0;
}

uint64_t syscall_ioctl(size_t fd, uint64_t cmd, void *arg) {
  syscall_file_t *file = CURRENT_PROC->fds[fd];
  if (!file)
    return -EBADF;
  return vfs_ioctl(file->file, cmd, arg);
}

size_t syscall_seek(size_t fd, ssize_t offset, int type) {
  syscall_file_t *file = CURRENT_PROC->fds[fd];
  if (!file)
    return -EBADF;
  if (ISFIFO(file->file))
    return -ESPIPE;

  switch (type) {
    case SEEK_END:
      file->file->offset = file->file->length + offset;
      return file->file->offset;
    case SEEK_CUR:
      if ((int64_t)file->file->offset + offset < 0)
        return -EINVAL;
      file->file->offset += offset;
      return file->file->offset;
    case SEEK_SET:
      if (offset < 0)
        return -EINVAL;
      file->file->offset = offset;
      return file->file->offset;
  }

  return -EINVAL;
}

int syscall_waitpid(ssize_t pid, int *status, int options) {
  return sched_waitpid(pid, status, options);
}

int syscall_access(char *path, int mode) {
  fs_file_t *file = vfs_open(path);

  if (!file)
    return -ENOENT;

  if (mode == F_OK) {
    vfs_close(file);
    return 0;
  } else if ((mode & R_OK && vfs_check_can_read(file, CURRENT_THREAD->uid,
                                                CURRENT_THREAD->gid)) ||
             (mode & W_OK && vfs_check_can_write(file, CURRENT_THREAD->uid,
                                                 CURRENT_THREAD->gid)) ||
             (mode & X_OK && vfs_check_can_exec(file, CURRENT_THREAD->uid,
                                                CURRENT_THREAD->gid))) {

    vfs_close(file);
    return -EACCES;
  }

  vfs_close(file);
  return 0;
}

int syscall_pipe(int pipefd[2]) {
  fs_file_t *file = vfs_mkfifo("unamed_fifo", 0777, CURRENT_THREAD->uid,
                               CURRENT_THREAD->gid, 0);
  if (!file)
    return -1;

  syscall_file_t *sfile_r = kmalloc(sizeof(syscall_file_t));
  *sfile_r = (syscall_file_t){
    .file = file,
    .flags = O_RDONLY,
  };

  syscall_file_t *sfile_w = kmalloc(sizeof(syscall_file_t));
  *sfile_w = (syscall_file_t){
    .file = file,
    .flags = O_WRONLY,
  };

  file->offset = 0;

  size_t i;
  for (i = 0; i < FDS_COUNT; i++)
    if (!CURRENT_PROC->fds[i]) {
      CURRENT_PROC->fds[i] = sfile_r;
      break;
    }
  if (i == FDS_COUNT) {
    vfs_close(file);
    kfree(sfile_r);
    kfree(sfile_w);
    return -EMFILE;
  }
  pipefd[0] = i;

  for (i = 0; i < FDS_COUNT; i++)
    if (!CURRENT_PROC->fds[i]) {
      CURRENT_PROC->fds[i] = sfile_w;
      break;
    }
  if (i == FDS_COUNT) {
    vfs_close(file);
    kfree(sfile_r);
    kfree(sfile_w);
    pipefd[0] = 0;
    return -EMFILE;
  }
  pipefd[1] = i;

  return 0;
}

int syscall_fcntl(int fd, int cmd, int arg) {
  syscall_file_t *file = CURRENT_PROC->fds[fd];
  if (!file)
    return -EBADF;

  switch (cmd) {
    case F_DUPFD:;
      syscall_file_t *new_file = kmalloc(sizeof(syscall_file_t));
      *new_file = *file;
      file->file->ref_count++;

      size_t i;
      for (i = arg; i < FDS_COUNT; i++)
        if (!CURRENT_PROC->fds[i]) {
          CURRENT_PROC->fds[i] = new_file;
          break;
        }
      return i;
  }

  return -EINVAL;
}

int syscall_remove(char *path) {
  fs_file_t *file = vfs_open(path);
  if (!file)
    return -ENOENT;
  if (vfs_check_can_write(file, CURRENT_THREAD->uid, CURRENT_THREAD->gid)) {
    vfs_close(file);
    return -EACCES;
  }
  if (S_ISDIR(file->mode))
    return vfs_rmdir(file);
  else
    return vfs_delete(file);
}

uint64_t c_syscall_handler(uint64_t rsp) {
  registers_t *registers = (registers_t *)rsp;

  uint64_t ret = registers->rax;

  switch (registers->rdi) {
    case SYSCALL_OPEN:
      ret = syscall_open((char *)registers->rsi, (int)registers->rdx,
                         (int)registers->rcx);
      break;
    case SYSCALL_CLOSE:
      ret = syscall_close((size_t)registers->rsi);
      break;
    case SYSCALL_READ:
      ret =
        syscall_read(registers->rsi, (uint8_t *)registers->rdx, registers->rcx);
      break;
    case SYSCALL_WRITE:
      ret = syscall_write(registers->rsi, (uint8_t *)registers->rdx,
                          registers->rcx);
      break;
    case SYSCALL_EXEC:
      ret = syscall_execve((char *)registers->rsi, (char **)registers->rdx,
                           (char **)registers->rcx);
      break;
    case SYSCALL_MMAP:
      ret = (uint64_t)syscall_mmap((mmap_args_t *)registers->rsi);
      break;
    case SYSCALL_MUNMAP:
      ret = (uint64_t)syscall_munmap((void *)registers->rsi,
                                     (size_t)registers->rdx);
      break;
    case SYSCALL_STAT:
      ret = syscall_stat((char *)registers->rsi, (stat_t *)registers->rdx);
      break;
    case SYSCALL_FSTAT:
      ret = syscall_fstat((size_t)registers->rsi, (stat_t *)registers->rdx);
      break;
    case SYSCALL_GETPID:
      ret = syscall_getpid();
      break;
    case SYSCALL_GETPPID:
      ret = syscall_getppid();
      break;
    case SYSCALL_EXIT:
      syscall_exit((int)registers->rsi);
      break;
    case SYSCALL_FORK:
      ret = syscall_fork(registers);
      break;
    case SYSCALL_GETTIMEOFDAY:
      syscall_gettimeofday((posix_time_t *)registers->rsi);
      break;
    case SYSCALL_FSYNC:
      syscall_fsync((size_t)registers->rsi);
      break;
    case SYSCALL_IOCTL:
      ret = syscall_ioctl((size_t)registers->rsi, registers->rdx,
                          (void *)registers->rcx);
      break;
    case SYSCALL_SEEK:
      ret =
        syscall_seek((size_t)registers->rsi, registers->rdx, registers->rcx);
      break;
    case SYSCALL_WAITPID:
      ret = syscall_waitpid((ssize_t)registers->rsi, (int *)registers->rdx,
                            registers->rcx);
      break;
    case SYSCALL_ACCESS:
      ret = syscall_access((char *)registers->rsi, registers->rdx);
      break;
    case SYSCALL_PIPE:
      ret = syscall_pipe((int *)registers->rsi);
      break;
    case SYSCALL_FCNTL:
      ret = syscall_fcntl((int)registers->rsi, (int)registers->rdx,
                          (int)registers->rcx);
      break;
    case SYSCALL_REMOVE:
      ret = syscall_remove((char *)registers->rsi);
      break;
    default:
      ret = -1;
      break;
  }

  return ret;
}
