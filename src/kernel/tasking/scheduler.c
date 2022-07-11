#include <assert.h>
#include <cpu_locals.h>
#include <dev/device.h>
#include <drivers/apic.h>
#include <elf.h>
#include <errno.h>
#include <event.h>
#include <fs/vfs.h>
#include <klog.h>
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

#define MAX_THREAD_COUNT 5000

#define DEFAULT_WAIT_TIMESLICE 20000
#define DEFAULT_TIMESLICE 5000

#define SCHED_STACK_TOP 0x70000000000
#define SCHED_MMAP_TOP 0x90000000000
#define SCHED_STACK_SIZE PAGE_SIZE * 0x40

extern void switch_and_run_stack(uintptr_t stack);

proc_t *kernel_proc = NULL;

static size_t current_pid = 0;
static size_t current_tid = 0;

static size_t total_threads_running = 0;
static size_t total_weight = 0;

static int sched_has_started = 0;

static lock_t sched_lock = {0};

static thread_t *threads[5000];

void sched_await() {
  while (!sched_has_started)
    ;

  asm volatile("cli");

  lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_WAIT_TIMESLICE);

  asm volatile("sti\n"
               "1:\n"
               "hlt\n"
               "jmp 1b\n"
               :
               :
               : "memory");
}

size_t sched_enqueue_thread(thread_t *thread) {
  LOCK(sched_lock);
  assert(thread);
  assert(!thread->queued);
  for (size_t i = 0; i < MAX_THREAD_COUNT; i++)
    if (!threads[i]) {
      threads[i] = thread;
      thread->queued = 1;
      total_threads_running++;
      total_weight += thread->weight;
      UNLOCK(sched_lock);
      return i;
    }
  klog(1, "Ran out of thread places in the thread queue!");
  while (1)
    ;
}

size_t sched_dequeue_thread(thread_t *thread) {
  LOCK(sched_lock);
  assert(thread);
  assert(thread->queued);
  assert(total_threads_running);
  for (size_t i = 0; i < MAX_THREAD_COUNT; i++)
    if (threads[i] == thread) {
      threads[i] = NULL;
      thread->queued = 0;
      total_threads_running--;
      total_weight -= thread->weight;
      UNLOCK(sched_lock);
      return i;
    }
  UNLOCK(sched_lock);
  return -1;
}

__attribute__((noreturn)) void sched_dequeue_and_die() {
  asm volatile("cli");

  thread_t *current_thread = get_locals()->current_thread;
  assert(current_thread);

  sched_dequeue_thread(current_thread);
  LOCK(sched_lock);
  kfree(current_thread);

  get_locals()->current_thread = NULL;

  pmm_free_pages((void *)current_thread->kernel_stack - PHYS_MEM_OFFSET -
  SCHED_STACK_SIZE,
  SCHED_STACK_SIZE / PAGE_SIZE);

  lapic_timer_stop();
  /* lapic_send_ipi(get_locals()->lapic_id, SCHEDULE_REG); */
  /* sched_await(); */

  lapic_timer_oneshot(SCHEDULE_REG, 20000);
  asm volatile("sti");

  UNLOCK(sched_lock);

  while (1)
    ;
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
    };

    /* new_proc->children.data = kcalloc(sizeof(proc_t *)); */
    /* new_proc->threads.data = kcalloc(sizeof(thread_t *)); */
    /* memset(new_proc->fds, 0, sizeof(syscall_file_t *) * FDS_COUNT); */

    /* for (size_t i = 0; i < FDS_COUNT; i++) */
      /* if (old_proc->fds[i]) { */
        /* syscall_file_t *sfile = kmalloc(sizeof(syscall_file_t)); */
        /* *sfile = *old_proc->fds[i]; */
        /* new_proc->fds[i] = sfile; */
        /* sfile->file->ref_count++; */
      /* } */
  }

  return new_proc;
}

thread_t *sched_new_thread(thread_t *thread, proc_t *parent, uintptr_t addr,
                           int weight, int uid, int gid) {
  if (!thread)
    thread = kcalloc(sizeof(thread_t));

  assert(thread);
  assert(parent);

  *thread = (thread_t){
    .gid = gid,
    .uid = uid,
    .blocked = 0,
    .parent = parent,
    .weight = weight,
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

  return thread;
}

int sched_fork(registers_t *regs) {
  proc_t *old_proc = get_locals()->current_thread->parent;
  (void)old_proc;
  /* thread_t *old_thread = get_locals()->current_thread; */

  proc_t *new_proc = sched_new_proc(old_proc, NULL, 1);
  (void)new_proc;
  /* thread_t *new_thread = kcalloc(sizeof(thread_t)); */

  /* printf("New proc PID: %lu\n", new_proc->pid); */
  printf("Fork\n");

  /* new_thread->regs = *regs; */
  /* new_thread->regs.rax = 0; */
  /* new_thread->regs.cs = GDT_SEG_UCODE; */
  /* new_thread->regs.ss = GDT_SEG_UDATA; */
  /* new_thread->parent = new_proc; */
  /* new_thread->weight = old_thread->weight; */
  /* new_thread->tid = current_tid++; */

  /* vec_push(&old_proc->children, new_proc); */
  /* vec_push(&new_proc->threads, new_thread); */

  /* new_thread->kernel_stack = (uintptr_t)pcalloc(SCHED_STACK_SIZE / PAGE_SIZE) + */
                             /* PHYS_MEM_OFFSET + SCHED_STACK_SIZE; */

  /* memcpy(new_thread->fpu_storage, old_thread->fpu_storage, 512); */
  /* memcpy((void *)new_thread->kernel_stack - SCHED_STACK_SIZE, */
  /* (void *)old_thread->kernel_stack - SCHED_STACK_SIZE, SCHED_STACK_SIZE); */

  /* sched_enqueue_thread(new_thread); */

  /* return new_proc->pid; */
  return 1;
}

void sched_exit(int code, int crashed) {
  printf("exiting\n");
  /* printf("called to exit!"); */

  /* code |= (crashed) ? 0x400 : 0x200; */
  /* code |= (crashed) ? ((code - 128) & 0xff) << 24 : (code & 0xff); */

  /* thread_t *current_thread = get_locals()->current_thread; */
  /* proc_t *current_proc = current_thread->parent; */

  /* pagemap_t *old_pagemap = current_proc->pagemap; */
  /* vmm_load_pagemap(&kernel_pagemap); */
  /* current_proc->pagemap = &kernel_pagemap; */

  /* for (size_t i = 0; i < FDS_COUNT; i++)  */
  /* if (current_proc->fds[i]) { */
  /* vfs_close(current_proc->fds[i]->file); */
  /* kfree(current_proc->fds[i]); */
  /* } */
  /* kfree(current_proc->fds); */

  /* assert(!current_proc->children.length); */

  /* vmm_destroy_pagemap(old_pagemap); */

  /* vec_remove(&current_proc->threads, get_locals()->current_thread); */

  /* LOCKED_WRITE(current_proc->status, code); */
  /* event_trigger(&current_proc->event); */

  while (1)
    ;

  sched_dequeue_and_die();
}

int sched_waitpid(ssize_t pid, int *status, int options) {
  /* printf("waitpid\n"); */
  /* thread_t *current_thread = get_locals()->current_thread; */
  /* proc_t *current_proc = current_thread->parent; */

  /* assert(current_thread); */
  /* assert(current_proc); */

  /* event_t **events = NULL; */
  /* proc_t *child = NULL; */
  /* size_t events_len = 0; */

  /* if (!current_proc->children.length) */
    /* return -ECHILD; */

  /* if (pid == -1) { */
    /* events_len = current_proc->children.length; */
    /* events = kcalloc(sizeof(event_t *) * events_len); */

    /* for (size_t i = 0; i < events_len; i++) */
      /* events[i] = &current_proc->children.data[i]->event; */
  /* } else if (pid > 0) { */
    /* for (size_t i = 0; i < (size_t)current_proc->children.length; i++) */
      /* if (current_proc->children.data[i]->pid == i) { */
        /* child = current_proc->children.data[i]; */
        /* events_len = 1; */
        /* events = kcalloc(sizeof(event_t *)); */
        /* events[0] = &child->event; */
        /* break; */
      /* } */
    /* if (!child) */
      /* return -ECHILD; */
  /* } else */
    /* return -EINVAL; */

  /* ssize_t which = event_await(events, events_len, !(options & WNOHANG)); */

  /* for (volatile size_t i = 0; i < 10000000000; i++) */
  /* for (volatile size_t i = 0; i < 1; i++) */
    /* asm volatile("nop"); */

  /* printf("Trying to exit"); */
  /* vmm_load_pagemap(current_proc->pagemap); */

  /* if (!child) */
  /* child = current_proc->children.data[which]; */
  /* assert(child); */

  /* if (status) */
  /* *status = child->status; */

  /* int ret = child->pid; */

  /* kfree(events); */

  /* vec_remove(&current_proc->children, child); */
  /* kfree(child); */

  /* (void)ret; */

  /* return ret; */
  *status = 0x200 | 69;
  return 0;
}

static inline thread_t *sched_get_next_thread(size_t orig_i,
                                              size_t *new_index) {
  size_t index = orig_i + 1;

  while (1) {
    if (index >= MAX_THREAD_COUNT)
      index = 0;

    thread_t *thread = threads[index];
    if (thread && !thread->blocked && (thread == get_locals()->current_thread ||
                   LOCK_ACQUIRE(thread->lock))) {
      *new_index = index;
      return thread;
    }

    if (index == orig_i) {
      *new_index = 0;
      return NULL;
    }

    index++;
  }
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
  size_t old_index = locals->last_run_thread_index;

  size_t new_index = 0;
  thread_t *new_current_thread = sched_get_next_thread(old_index, &new_index);

  if (!new_current_thread) {
    locals->last_run_thread_index = 0;
    locals->current_thread = NULL;
    lapic_eoi();
    lapic_timer_oneshot(SCHEDULE_REG, DEFAULT_TIMESLICE);
    UNLOCK(sched_lock);
    return;
  }

  if (current_thread) {
    if (new_index == old_index) {
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
  locals->last_run_thread_index = new_index;
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

  if ((argc + envc + 1) & 1)
    stack--;

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
  /* thread->regs.rsp -= (thread->regs.rsp & 16); */
}

int sched_run_program(char *path, char *argv[], char *env[], char *stdin,
                      char *stdout, char *stderr, int replace) {
  pagemap_t *new_pagemap = vmm_create_new_pagemap();

  uintptr_t entry;
  int loaded = elf_load_binary(path, new_pagemap, &entry);
  assert(loaded);

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
      NULL, new_proc, entry, get_locals()->current_thread->weight,
      get_locals()->current_thread->uid, get_locals()->current_thread->gid);

    sched_load_args_to_stack(
      new_thread,
      vmm_range_to_addr(new_proc->pagemap,
                        new_thread->regs.rsp - SCHED_STACK_SIZE) +
        SCHED_STACK_SIZE + PHYS_MEM_OFFSET,
      new_thread->regs.rsp, argv, env);

    sched_enqueue_thread(new_thread);
  } else {
    /* printf("Call to execve\n"); */

    thread_t *thread = get_locals()->current_thread;
    proc_t *proc = thread->parent;
    /* pagemap_t *old_pagemap = proc->pagemap; */

    proc->mmap_top = SCHED_MMAP_TOP;
    proc->stack_top = SCHED_STACK_TOP;
    proc->pagemap = new_pagemap;
    proc->mmaped_len = 0;

    sched_new_thread(thread, proc, entry, thread->weight, thread->uid,
                     thread->gid);

    LOCK(sched_lock);

    sched_load_args_to_stack(
      thread,
      vmm_range_to_addr(proc->pagemap, thread->regs.rsp - SCHED_STACK_SIZE) +
        SCHED_STACK_SIZE + PHYS_MEM_OFFSET,
      thread->regs.rsp, argv, env);

    thread->queued = 1;

    vmm_load_pagemap(new_pagemap);
    /* vmm_destroy_pagemap(old_pagemap); */

    UNLOCK(sched_lock);
    asm volatile("cli");
    /* switch_and_run_stack((uintptr_t)&thread->regs); */
    sched_await();
  }

  return 0;
}

void init_sched(uintptr_t start_addr) {
  kernel_proc = sched_new_proc(NULL, NULL, 0);
  thread_t *new_thread =
    sched_new_thread(NULL, kernel_proc, start_addr, 100, 0, 0);
  sched_enqueue_thread(new_thread);

  LOCKED_WRITE(sched_has_started, 1);
  sched_await();
}
