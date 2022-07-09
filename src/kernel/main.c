#include <acpi/acpi.h>
#include <boot/stivale2.h>
#include <cpu_locals.h>
#include <dev/device.h>
#include <dev/fbdev.h>
#include <dev/mousedev.h>
#include <dev/tty.h>
#include <drivers/ahci.h>
#include <drivers/apic.h>
#include <drivers/mbr.h>
#include <drivers/pcspkr.h>
#include <drivers/pit.h>
#include <drivers/ps2.h>
#include <drivers/rtc.h>
#include <drivers/serial.h>
#include <elf.h>
#include <fb/fb.h>
#include <fs/devfs.h>
#include <fs/fat32.h>
#include <fs/tmpfs.h>
#include <fs/vfs.h>
#include <klog.h>
#include <main.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <pci/pci.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/gdt.h>
#include <sys/idt.h>
#include <sys/irq.h>
#include <sys/isr.h>
#include <sys/syscall.h>
#include <tasking/scheduler.h>
#include <tasking/smp.h>

extern void enable_sse();

void *stivale2_get_tag(struct stivale2_struct *stivale2_struct, uint64_t id) {
  struct stivale2_tag *current_tag = (void *)stivale2_struct->tags;
  while (1) {
    if (!current_tag)
      return NULL;
    else if (current_tag->identifier == id)
      return current_tag;
    current_tag = (void *)current_tag->next;
  }
}

void k_thread2() {
  /* printf("Hello from thread 2!\n"); */
  while (1) {
    /* printf("Thread 2\n"); */
  }
}

void k_thread() {
  klog(3, "Scheduler started and running\n");
  klog_init(init_rtc(), "Real time clock");
  klog_init(init_serial(), "Serial");
  klog_init(pci_enumerate(), "PCI");
  klog_init(init_pit(), "PIT");
  klog_init(init_pcspkr(), "PC speaker");
  klog_init(init_sata(), "SATA");
  klog_init(init_ps2(), "PS2");
  klog_init(init_vfs(), "Virtual filesystem");
  klog_init(init_tmpfs(), "TMPFS");
  klog_init(init_devfs(), "DEVFS");
  klog_init(init_fat(), "FAT32");

  vfs_mount("/", device_get(0), "FAT32");
  vfs_mount("/dev/", NULL, "DEVFS");

  klog_init(init_tty("/dev"), "TTY0");
  klog_init(init_fbdev("/dev"), "Framebuffer device");
  klog_init(init_mousedev("/dev"), "Mouse device");

  /* fs_file_t *tty0 = vfs_open("/dev/tty0"); */

  /* syscall_file_t *fil = kmalloc(sizeof(syscall_file_t)); */
  /* *fil = (syscall_file_t){ */
  /* .file = tty0, */
  /* .flags = O_RDWR, */
  /* }; */

  /* tty0->offset = 0; */

  /* proc_t *user_proc = sched_new_proc(0, 0, 1, 0, NULL, 0, 0, 0, 0, 0); */
  /* user_proc->fds[0] = fil; */
  /* user_proc->fds[1] = fil; */
  /* user_proc->fds[2] = fil; */

  /* sched_execve("/prog/forktest", NULL, NULL, "/dev/tty0", "/dev/tty0",
   * "/dev/tty0", 0); */
  /* char *env[2] = {"PATH=/prog", NULL}; */
  /* sched_execve("/prog/shell", NULL, env, "/dev/tty0", "/dev/tty0",
   * "/dev/tty0", */
  /* 0); */

  /* elf_run_binary("/prog/img", user_proc, 1); */

  /* sched_new_thread(NULL, kernel_proc, (uintptr_t)k_thread2, 5, 0, 0, 1); */
  /* sched_new_thread(NULL, kernel_proc, (uintptr_t)k_thread2, 0, 0, 0, 1); */
  /* sched_new_thread(NULL, kernel_proc, (uintptr_t)k_thread2, 0, 0, 0, 1); */

  /* sched_run_program("/prog/img", NULL, NULL, "/dev/tty0", "/dev/tty0",
   * "/dev/tty0", 0); */
  /* char *args[2] = {"Hello, world!\n", NULL}; */
  /* sched_run_program("/prog/forktest", args, NULL, "/dev/tty0", "/dev/tty0",
   * "/dev/tty0", 0); */

  char *args[] = {"PATH=/prog", NULL};
  sched_run_program("/prog/shell", NULL, args, "/dev/tty0", "/dev/tty0",
                    "/dev/tty0", 0);
  /* sched_run_program("/prog/trig", NULL, args, "/dev/tty0", "/dev/tty0", */
  /* "/dev/tty0", 0); */

  while (1) {
    /* printf("Thread 1\n"); */
  }
  while (1)
    ;
}

void kernel_main(struct stivale2_struct *bootloader_info) {
  struct stivale2_struct_tag_framebuffer *framebuffer_info =
    (struct stivale2_struct_tag_framebuffer *)stivale2_get_tag(
      bootloader_info, STIVALE2_STRUCT_TAG_FRAMEBUFFER_ID);
  struct stivale2_struct_tag_memmap *memory_info =
    (struct stivale2_struct_tag_memmap *)stivale2_get_tag(
      bootloader_info, STIVALE2_STRUCT_TAG_MEMMAP_ID);
  struct stivale2_struct_tag_rsdp *rsdp_info =
    (struct stivale2_struct_tag_rsdp *)stivale2_get_tag(
      bootloader_info, STIVALE2_STRUCT_TAG_RSDP_ID);
  struct stivale2_struct_tag_smp *smp_info =
    (struct stivale2_struct_tag_smp *)stivale2_get_tag(
      bootloader_info, STIVALE2_STRUCT_TAG_SMP_ID);

  enable_sse();

  init_gdt();

  init_pmm(memory_info);
  init_vmm(memory_info);

  init_idt();
  init_syscalls();
  init_isr();
  init_irq();

  disable_pic();

  klog_init(init_fb(framebuffer_info), "Framebuffer");
  klog_init(init_acpi(rsdp_info), "ACPI");
  klog_init(init_smp(smp_info), "SMP");

  init_sched((uintptr_t)k_thread);
}
