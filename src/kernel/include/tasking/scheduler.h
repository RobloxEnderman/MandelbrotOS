#ifndef __SCHEDULER_H__
#define __SCHEDULER_H__

#include <event.h>
#include <lock.h>
#include <mm/vmm.h>
#include <registers.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

#define FDS_COUNT 128
#define PRIORITY_LEVELS 20

#define WNOHANG 1

struct proc;

typedef struct thread {
  struct proc *parent;
  int alive;
  int gid;
  int uid;
  size_t tid;
  lock_t lock;
  int queued;
  int priority;
  uintptr_t kernel_stack;
  size_t which_event;
  registers_t regs;
  uint8_t fpu_storage[512] __attribute__((aligned(16)));
} thread_t;

typedef struct proc {
  int user;
  size_t pid;
  struct proc *parent;
  vec_t(struct proc *) children;
  vec_t(thread_t *) threads;
  pagemap_t *pagemap;
  uintptr_t stack_top;
  uintptr_t mmap_top;
  size_t mmaped_len;
  syscall_file_t *fds[FDS_COUNT];
  event_t *event;
  int status;
} proc_t;

extern proc_t *kernel_proc;

void init_sched(uintptr_t start_addr);
void sched_await();
proc_t *sched_new_proc(proc_t *old_proc, pagemap_t *pagemap, int user);
thread_t *sched_new_thread(thread_t *thread, proc_t *parent, uintptr_t addr,
                           int priority, int uid, int gid, int auto_start);
int sched_fork(registers_t *regs);
int sched_run_program(char *path, char *argv[], char *env[], char *stdin,
                      char *stdout, char *stderr, int replace);
int sched_waitpid(ssize_t pid, int *status, int options);
void sched_exit(int code, int crashed);

#endif
