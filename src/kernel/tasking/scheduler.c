#include <cpu_locals.h>
#include <dev/device.h>
#include <drivers/apic.h>
#include <elf.h>
#include <errno.h>
#include <event.h>
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
#include <sys/syscall.h>
#include <tasking/scheduler.h>
#include <vec.h>

#define DEFAULT_WAIT_TIMESLICE 20000
#define DEFAULT_TIMESLICE 5000

#define SCHED_STACK_TOP 0x70000000000
#define SCHED_MMAP_TOP 0x90000000000
#define SCHED_STACK_SIZE PAGE_SIZE * 0x40

extern void switch_and_run_stack(uintptr_t stack);

proc_t *kernel_proc = NULL;

static size_t current_pid = 0;
static size_t current_tid = 0;

static int sched_has_started = 0;

static lock_t sched_lock = {0};

static vec_t(thread_t *) threads[PRIORITY_LEVELS];

void sched_await() {
  while (!sched_has_started)
    ;

  asm volatile("cli");

  lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_WAIT_TIMESLICE);

  asm volatile("sti\n"
               "1:\n"
               "hlt\n"
               "jmp 1b\n");
}

void sched_enqueue(thread_t *thread) {
  if (thread->queued)
    return;
  thread->queued = 1;
  LOCK(sched_lock);
  vec_push(&threads[thread->priority], thread);
  UNLOCK(sched_lock);
}

proc_t *sched_new_proc(proc_t *old_proc, pagemap_t *pagemap, int user) {
  proc_t *new_proc = kcalloc(sizeof(proc_t));

  if (!old_proc) {
    if (!pagemap) {
      if (user)
        pagemap = vmm_create_new_pagemap();
      else
        pagemap = &kernel_pagemap;
    }

    *new_proc = (proc_t){
      .mmap_top = SCHED_MMAP_TOP,
      .stack_top = SCHED_STACK_TOP,
      .parent = NULL,
      .pagemap = pagemap,
      .user = user,
      .pid = current_pid++,
      .status = 0,
      .event = kcalloc(sizeof(event_t)),
    };

    new_proc->children.data = kcalloc(sizeof(proc_t *));
    new_proc->threads.data = kcalloc(sizeof(thread_t *));
    memset(new_proc->fds, 0, sizeof(syscall_file_t *) * FDS_COUNT);
  } else {
    *new_proc = (proc_t){
      .mmap_top = old_proc->mmap_top,
      .stack_top = old_proc->stack_top,
      .parent = old_proc,
      .user = user,
      .pid = current_pid++,
      .pagemap = vmm_fork_pagemap(old_proc->pagemap),
      .status = 0,
      .event = kcalloc(sizeof(event_t)),
    };

    new_proc->children.data = kcalloc(sizeof(proc_t *));
    new_proc->threads.data = kcalloc(sizeof(thread_t *));
    memset(new_proc->fds, 0, sizeof(syscall_file_t *) * FDS_COUNT);

    for (size_t i = 0; i < FDS_COUNT; i++)
      if (old_proc->fds[i]) {
        syscall_file_t *sfile = kmalloc(sizeof(syscall_file_t));
        *sfile = *old_proc->fds[i];
        new_proc->fds[i] = sfile;
        sfile->file->ref_count++;
      }
  }

  return new_proc;
}

thread_t *sched_new_thread(thread_t *thread, proc_t *parent, uintptr_t addr,
                           int priority, int uid, int gid, int auto_start) {
  if (!thread)
    thread = kcalloc(sizeof(thread_t));
  if (!parent)
    return NULL;

  *thread = (thread_t){
    .gid = gid,
    .uid = uid,
    .parent = parent,
    .alive = 1,
    .priority = priority,
    .tid = current_tid++,
    .queued = 0,
    .fpu_storage = {0},
    .regs =
      (registers_t){
        .rip = addr,
        .cs = (parent->user) ? GDT_SEG_UCODE : GDT_SEG_KCODE,
        .ss = (parent->user) ? GDT_SEG_UDATA : GDT_SEG_KDATA,
        .rflags = 0x202,
        .rax = 0,
      },
  };

  UNLOCK(thread->lock);

  asm volatile("fxsave %0" : "+m"(thread->fpu_storage) : : "memory");

  if (parent->user) {
    uintptr_t user_stack = (uintptr_t)pcalloc(SCHED_STACK_SIZE / PAGE_SIZE);
    uintptr_t kernel_stack = (uintptr_t)pcalloc(SCHED_STACK_SIZE / PAGE_SIZE);

    uintptr_t virt_stack = parent->stack_top;
    parent->stack_top -= SCHED_STACK_SIZE;

    vmm_mmap_range(parent->pagemap, user_stack, virt_stack, SCHED_STACK_SIZE,
                   MAP_ANON | MAP_PRIVATE | MAP_FIXED,
                   PROT_READ | PROT_WRITE | PROT_EXEC);

    thread->regs.rsp = virt_stack + SCHED_STACK_SIZE;
    thread->kernel_stack = kernel_stack + PHYS_MEM_OFFSET + SCHED_STACK_SIZE;
  } else
    thread->regs.rsp = thread->kernel_stack =
      (uintptr_t)pcalloc(SCHED_STACK_SIZE / PAGE_SIZE) + PHYS_MEM_OFFSET +
      SCHED_STACK_SIZE;

  int i;
  vec_find(&parent->threads, thread, i);
  if (i == -1)
    vec_push(&parent->threads, thread);

  if (auto_start)
    sched_enqueue(thread);

  return thread;
}

static inline thread_t *sched_get_next_thread(size_t orig_i, int priority,
                                              size_t *new_index) {
  size_t index = orig_i + 1;

  while (1) {
    if (index >= (size_t)threads[priority].length)
      index = 0;

    thread_t *thread = threads[priority].data[index];
    if (thread && (thread == get_locals()->current_thread ||
                   LOCK_ACQUIRE(thread->lock))) {
      *new_index = index;
      return thread;
    }

    if (index == orig_i)
      return NULL;

    index++;
  }
}

int sched_fork(registers_t *regs) {
  proc_t *old_proc = get_locals()->current_thread->parent;

  proc_t *new_proc = sched_new_proc(old_proc, NULL, 1);
  thread_t *new_thread = kcalloc(sizeof(thread_t));

  new_thread->regs = *regs;
  new_thread->regs.rax = 0;
  new_thread->parent = new_proc;
  new_thread->priority = get_locals()->current_thread->priority;
  new_thread->tid = current_tid++;
  new_thread->kernel_stack = (uintptr_t)pcalloc(SCHED_STACK_SIZE / PAGE_SIZE) +
                             PHYS_MEM_OFFSET + SCHED_STACK_SIZE;

  memcpy(new_thread->fpu_storage, get_locals()->current_thread->fpu_storage,
         512);

  sched_enqueue(new_thread);
  vec_push(&old_proc->children, new_proc);

  return new_proc->pid;
}

void sched_destroy_thread(thread_t *thread) {
  pmm_free_pages((void *)thread->kernel_stack - PHYS_MEM_OFFSET -
                   SCHED_STACK_SIZE,
                 SCHED_STACK_SIZE / PAGE_SIZE);
  if (thread->queued)
    vec_remove(&threads[thread->priority], thread);
  kfree(thread);
}

void sched_exit(int code, int crashed) {
  code |= (crashed) ? 0x400 : 0x200;
  code |= (crashed) ? ((code - 128) & 0xff) << 24 : (code & 0xff);

  proc_t *proc = get_locals()->current_thread->parent;
  pagemap_t *old_pagemap = proc->pagemap;

  proc->pagemap = &kernel_pagemap;
  vmm_load_pagemap(&kernel_pagemap);

  for (size_t i = 0; i < FDS_COUNT; i++)
  if (proc->fds[i]) {
  vfs_close(proc->fds[i]->file);
  kfree(proc->fds[i]);
  }
  kfree(proc->fds);

  vmm_destroy_pagemap(old_pagemap);

  LOCKED_WRITE(proc->status, code);
  event_trigger(proc->event);

  asm volatile("cli");
  vec_remove(&threads[get_locals()->current_thread->priority],
             get_locals()->current_thread);
  pmm_free_pages((void *)(get_locals()->current_thread->kernel_stack - PHYS_MEM_OFFSET - SCHED_STACK_SIZE), SCHED_STACK_SIZE / PAGE_SIZE);
  kfree(get_locals()->current_thread);
  get_locals()->current_thread = NULL;
  sched_await();
}

int sched_waitpid(ssize_t pid, int *status, int options) {
  proc_t *proc = get_locals()->current_thread->parent;
  proc_t *child = NULL;

  event_t **events;
  size_t events_len;

  if (pid == -1) {
    events = kcalloc(proc->children.length * sizeof(event_t *));
    events_len = proc->children.length;
    for (size_t i = 0; i < events_len; i++)
      events[i] = proc->children.data[i]->event;
  } else if (pid > 0) {
    events = kcalloc(sizeof(event_t *));
    events_len = 1;
    for (size_t i = 0; i < (size_t)proc->children.length; i++)
      if (proc->children.data[i]->pid == (size_t)pid) {
        *events = proc->children.data[i]->event;
        child = proc->children.data[i];
      }
    if (!*events)
      return -ECHILD;
  } else
    return -EINVAL;

  ssize_t which = event_await(events, events_len, !(options & WNOHANG));

  if (which == -1)
    return 0;
  if (!child)
    child = proc->children.data[which];

  int ret = child->pid;

  if (status)
  *status = child->status;

  vec_remove(&proc->children, child);
  kfree(child->event);
  kfree(child);
  kfree(events);

  return ret;
}

void schedule(uint64_t rsp) {
  lapic_timer_stop();

  if (!LOCK_ACQUIRE(sched_lock)) {
    lapic_eoi();
    lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_TIMESLICE);
    return;
  }

  cpu_locals_t *locals = get_locals();
  thread_t *current_thread = locals->current_thread;
  size_t old_index = locals->last_run_thread_index[locals->current_priority];
  int old_priority = locals->current_priority;

  do {
    locals->current_priority++;
    if (locals->current_priority > locals->current_priority_peg) {
      locals->current_priority = 0;
      locals->current_priority_peg++;
      if (locals->current_priority_peg == PRIORITY_LEVELS)
        locals->current_priority_peg = 0;
    }
  } while (!threads[locals->current_priority].length);

  size_t new_index = (size_t)-1;
  thread_t *new_current_thread = sched_get_next_thread(
    locals->last_run_thread_index[locals->current_priority],
    locals->current_priority, &new_index);

  if (!new_current_thread) {
    lapic_eoi();
    lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_TIMESLICE);
    UNLOCK(sched_lock);
    return;
  }

  if (current_thread) {
    if (locals->current_priority == old_priority && new_index == old_index) {
      lapic_eoi();
      lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_TIMESLICE);
      UNLOCK(sched_lock);
      return;
    }
    asm volatile("fxsave %0" : "+m"(current_thread->fpu_storage) : : "memory");
    current_thread->regs = *((registers_t *)rsp);
    UNLOCK(current_thread->lock);
  }

  locals->current_thread = new_current_thread;
  locals->last_run_thread_index[locals->current_priority] = new_index;
  current_thread = new_current_thread;

  asm volatile("fxrstor %0" : : "m"(current_thread->fpu_storage) : "memory");

  locals->tss.rsp[0] = current_thread->kernel_stack;

  lapic_eoi();
  lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_TIMESLICE);

  vmm_load_pagemap(current_thread->parent->pagemap);

  UNLOCK(sched_lock);

  switch_and_run_stack((uintptr_t)&current_thread->regs);
}

static inline void sched_load_args_to_stack(thread_t *thread,
                                            uintptr_t phys_addr,
                                            uintptr_t virt_addr, char *argv[],
                                            char *env[]) {
  size_t argc = 0;
  size_t envc = 0;

  uintptr_t stack_top = phys_addr;
  uint64_t *stack = (size_t *)stack_top;

  if (env)
    for (char **elem = (char **)env; *elem; elem++) {
      stack = (void *)stack - (strlen(*elem) + 1);
      strcpy((char *)stack, *elem);
      envc++;
    }

  if (argv)
    for (char **elem = (char **)argv; *elem; elem++) {
      stack = (void *)stack - (strlen(*elem) + 1);
      strcpy((char *)stack, *elem);
      argc++;
    }

  stack = (void *)stack - ((uintptr_t)stack & 0xf);

  uintptr_t sa = virt_addr;

  if (env) {
    *(--stack) = 0;
    stack -= envc;
    for (size_t i = 0; i < envc; i++) {
      sa -= strlen(env[i]) + 1;
      stack[i] = sa;
    }
  }
  void *envp_addr = stack;

  if (argv) {
    *(--stack) = 0;
    stack -= argc;
    for (size_t i = 0; i < argc; i++) {
      sa -= strlen(argv[i]) + 1;
      stack[i] = sa;
    }
  }
  void *argv_addr = stack;

  thread->regs.rdi = argc;
  thread->regs.rsi =
    (argv) ? (uintptr_t)virt_addr - (stack_top - (uintptr_t)argv_addr) : 0;
  thread->regs.rdx =
    (env) ? (uintptr_t)virt_addr - (stack_top - (uintptr_t)envp_addr) : 0;
  thread->regs.rsp -= stack_top - (uintptr_t)stack;
  thread->regs.rsp -= (thread->regs.rsp & 8);
}

int sched_run_program(char *path, char *argv[], char *env[], char *stdin,
                      char *stdout, char *stderr, int replace) {
  pagemap_t *new_pagemap = vmm_create_new_pagemap();

  uintptr_t entry;
  elf_run_binary(path, new_pagemap, &entry);

  if (!replace) {
    proc_t *new_proc = sched_new_proc(NULL, new_pagemap, 1);
    new_proc->parent = get_locals()->current_thread->parent;

    if (stdin) {
      fs_file_t *file = vfs_open(stdin);
      syscall_file_t *sfile = kcalloc(sizeof(syscall_file_t));
      *sfile = (syscall_file_t){
        .file = file,
        .flags = O_RDONLY,
      };
      new_proc->fds[0] = sfile;
    }
    if (stdout) {
      fs_file_t *file = vfs_open(stdout);
      syscall_file_t *sfile = kcalloc(sizeof(syscall_file_t));
      *sfile = (syscall_file_t){
        .file = file,
        .flags = O_WRONLY,
      };
      new_proc->fds[1] = sfile;
    }
    if (stderr) {
      fs_file_t *file = vfs_open(stderr);
      syscall_file_t *sfile = kcalloc(sizeof(syscall_file_t));
      *sfile = (syscall_file_t){
        .file = file,
        .flags = O_WRONLY,
      };
      new_proc->fds[2] = sfile;
    }

    thread_t *new_thread = sched_new_thread(
      NULL, new_proc, entry, get_locals()->current_thread->priority,
      get_locals()->current_thread->uid, get_locals()->current_thread->gid, 0);

    sched_load_args_to_stack(
      new_thread,
      vmm_range_to_addr(new_proc->pagemap,
                        new_thread->regs.rsp - SCHED_STACK_SIZE) +
        SCHED_STACK_SIZE + PHYS_MEM_OFFSET,
      new_thread->regs.rsp, argv, env);

    sched_enqueue(new_thread);
  } else {
    thread_t *thread = get_locals()->current_thread;
    proc_t *proc = thread->parent;
    pagemap_t *old_pagemap = proc->pagemap;

    proc->mmap_top = SCHED_MMAP_TOP;
    proc->stack_top = SCHED_STACK_TOP;
    proc->mmaped_len = 0;
    proc->pagemap = new_pagemap;

    sched_new_thread(thread, proc, entry, thread->priority, thread->uid,
                     thread->gid, 0);

    sched_load_args_to_stack(
      thread,
      vmm_range_to_addr(proc->pagemap, thread->regs.rsp - SCHED_STACK_SIZE) +
        SCHED_STACK_SIZE + PHYS_MEM_OFFSET,
      thread->regs.rsp, argv, env);

    vmm_load_pagemap(new_pagemap);
    vmm_destroy_pagemap(old_pagemap);

    asm volatile("cli");
    switch_and_run_stack((uintptr_t)&thread->regs);
  }

  return 0;
}

void init_sched(uintptr_t start_addr) {
  for (size_t i = 0; i < PRIORITY_LEVELS; i++)
    threads[i].data = kcalloc(sizeof(thread_t *));

  kernel_proc = sched_new_proc(NULL, NULL, 0);
  sched_new_thread(NULL, kernel_proc, start_addr, 0, 0, 0, 1);

  LOCKED_WRITE(sched_has_started, 1);
  sched_await();
}
