#include <acpi/acpi.h>
#include <boot/stivale2.h>
#include <cpu_locals.h>
#include <drivers/ahci.h>
#include <drivers/apic.h>
#include <drivers/kbd.h>
#include <drivers/mbr.h>
#include <drivers/pcspkr.h>
#include <drivers/pit.h>
#include <drivers/rtc.h>
#include <drivers/serial.h>
#include <fb/fb.h>
#include <fs/fat32.h>
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

void user_thread() {
  size_t index;
  syscall(SYSCALL_OPEN, (uint64_t) "A:/boot/limine.cfg", (uint64_t)&index, 0);

  volatile uint8_t buf[100] = {0};
  syscall(SYSCALL_READ, index, (volatile uint64_t)buf, 88);

  for (volatile size_t i = 0; i < 88;
       i++) { // Naughty compiler likes to screw with my beautiful for loop. For
              // this reason, we must make it not be messed with and make it
              // volatile
    if (buf[i] == '\n')
      syscall(SYSCALL_PRINT, (uint64_t) "\r\n", 0, 0);
    else
      syscall(SYSCALL_PUTCHAR, (uint64_t)buf[i], 0, 0);
  }

  while (1)
    ;
}

void k_thread() {
  klog(3, "Scheduler started and running\r\n");
  klog_init(init_rtc(), "Real time clock");
  klog_init(init_serial(), "Serial");
  klog_init(init_kbd(), "Keyboard");
  klog_init(pci_enumerate(), "PCI");
  klog_init(init_pit(), "PIT");
  klog_init(init_pcspkr(), "PC speaker");
  if (klog_init(init_sata(), "SATA"))
    while (1)
      ;

  klog(parse_mbr(), "Master boot record parsed\r\n");
  klog_init(init_fat(), "FAT filesystem");
  klog_init(init_vfs(), "Virtual filesystem");

  proc_t *user_proc = create_proc("u_proc", 1);
  create_thread("u_test", (uintptr_t)user_thread, 5000, 1, 1, user_proc);

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

  init_gdt();
  init_idt();
  init_isr();
  init_irq();

  init_pmm(memory_info);
  init_vmm();

  disable_pic();

  klog_init(init_fb(framebuffer_info), "Framebuffer");
  klog_init(init_acpi(rsdp_info), "ACPI");
  klog_init(init_syscalls(), "System calls");
  klog_init(init_smp(smp_info), "SMP");

  scheduler_init((uintptr_t)k_thread, smp_info);
}
