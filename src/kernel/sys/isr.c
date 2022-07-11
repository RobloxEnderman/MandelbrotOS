#include <cpu_locals.h>
#include <drivers/serial.h>
#include <mm/vmm.h>
#include <printf.h>
#include <registers.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/gdt.h>
#include <sys/idt.h>
#include <sys/isr.h>
#include <tasking/scheduler.h>

#define DEBUG_FAULTS

extern void isr0();
extern void isr1();
extern void isr2();
extern void isr3();
extern void isr4();
extern void isr5();
extern void isr6();
extern void isr7();
extern void isr8();
extern void isr9();
extern void isr10();
extern void isr11();
extern void isr12();
extern void isr13();
extern void isr14();
extern void isr15();
extern void isr16();
extern void isr17();
extern void isr18();
extern void isr19();
extern void isr20();
extern void isr21();
extern void isr22();
extern void isr23();
extern void isr24();
extern void isr25();
extern void isr26();
extern void isr27();
extern void isr28();
extern void isr29();
extern void isr30();
extern void isr31();

char *exception_messages[] = {
  "Division By Zero",
  "Debug",
  "Non Maskable Interrupt",
  "Breakpoint",
  "Into Detected Overflow",
  "Out of Bounds",
  "Invalid Opcode",
  "Device not Available",
  "Double Fault",
  "Coprocessor Segment Overrun",
  "Bad TSS",
  "Segment Not Present",
  "Stack Fault Exception",
  "General Protection Fault",
  "Page Fault",
  "[RESERVED]",
  "Floating Point Exception",
  "Alignment Check",
  "Machine Check",
  "SIMD Floating Point Exception",
  "Virtualization Exception",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "[RESERVED]",
  "Security Exception",
};

int init_isr() {
  idt_set_gate(&idt[0], 0, 1, isr0);
  idt_set_gate(&idt[1], 0, 1, isr1);
  idt_set_gate(&idt[2], 0, 1, isr2);
  idt_set_gate(&idt[3], 0, 1, isr3);
  idt_set_gate(&idt[4], 0, 1, isr4);
  idt_set_gate(&idt[5], 0, 1, isr5);
  idt_set_gate(&idt[6], 0, 1, isr6);
  idt_set_gate(&idt[7], 0, 1, isr7);
  idt_set_gate(&idt[8], 0, 1, isr8);
  idt_set_gate(&idt[9], 0, 1, isr9);
  idt_set_gate(&idt[10], 0, 1, isr10);
  idt_set_gate(&idt[11], 0, 1, isr11);
  idt_set_gate(&idt[12], 0, 1, isr12);
  idt_set_gate(&idt[13], 0, 1, isr13);
  idt_set_gate(&idt[14], 0, 1, isr14);
  idt_set_gate(&idt[15], 0, 1, isr15);
  idt_set_gate(&idt[16], 0, 1, isr16);
  idt_set_gate(&idt[17], 0, 1, isr17);
  idt_set_gate(&idt[18], 0, 1, isr18);
  idt_set_gate(&idt[19], 0, 1, isr19);
  idt_set_gate(&idt[20], 0, 1, isr20);
  idt_set_gate(&idt[21], 0, 1, isr21);
  idt_set_gate(&idt[22], 0, 1, isr22);
  idt_set_gate(&idt[23], 0, 1, isr23);
  idt_set_gate(&idt[24], 0, 1, isr24);
  idt_set_gate(&idt[25], 0, 1, isr25);
  idt_set_gate(&idt[26], 0, 1, isr26);
  idt_set_gate(&idt[27], 0, 1, isr27);
  idt_set_gate(&idt[28], 0, 1, isr28);
  idt_set_gate(&idt[29], 0, 1, isr29);
  idt_set_gate(&idt[30], 0, 1, isr30);
  idt_set_gate(&idt[31], 0, 1, isr31);

  return 0;
}

void c_isr_handler(uint64_t ex_no, uint64_t err, uint64_t rsp) {
  vmm_load_pagemap(&kernel_pagemap);

#ifdef DEBUG_FAULTS
  printf("\nCPU %lu: %s at %lx\n", get_locals()->cpu_number,
         exception_messages[ex_no], ((registers_t *)rsp)->rip);
  printf("PID: %lu\n", get_locals()->current_thread->parent->pid);
  printf("Err: %lu\n", err);

  printf("Stack trace:\n%lx\n", ((registers_t *)rsp)->rip);
  uint64_t rbp = ((registers_t *)rsp)->rbp;
  while (rbp) {
    uint64_t rip = ((uint64_t *)(vmm_get_kernel_address(
      get_locals()->current_thread->parent->pagemap, rbp)))[1];
    printf("%lx\n", rip);
    rbp = *((uint64_t *)(vmm_get_kernel_address(
      get_locals()->current_thread->parent->pagemap, rbp)));
  }
#endif

  int exit_code = 0;
  switch (ex_no) {
    case 0:
    case 19:
    case 16:
      exit_code = SIGFPE;
      break;
    case 13:
    case 14:
      exit_code = SIGSEGV;
      break;
    case 6:
      exit_code = SIGILL;
      break;
  }

  sched_exit(exit_code + 128, 1);
}
