#include <boot/stivale2.h>
#include <cpu_locals.h>
#include <drivers/apic.h>
#include <klog.h>
#include <lock.h>
#include <mm/kheap.h>
#include <mm/pmm.h>
#include <mm/vmm.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/gdt.h>
#include <sys/idt.h>
#include <tasking/scheduler.h>
#include <tasking/smp.h>

static cpu_locals_t *cpu_locals;
static uint32_t bsp_lapic_id;
static size_t inited_cpus = 0;

extern void enable_sse();

void smp_init_cpu(struct stivale2_smp_info *smp_info) {
  if (smp_info->lapic_id != bsp_lapic_id) {
    enable_sse();
    load_gdt();
    load_idt();
  }

  vmm_load_pagemap(&kernel_pagemap);

  cpu_locals_t *locals = (cpu_locals_t *)smp_info->extra_argument;

  set_and_load_tss((uintptr_t)&locals->tss);

  locals->lapic_id = smp_info->lapic_id;
  locals->last_run_thread_index = 0;
  locals->current_thread = NULL;

  set_locals(locals);

  init_lapic();
  lapic_timer_get_freq();

  klog(3, "Brought up CPU #%lu\n", locals->cpu_number);

  LOCKED_INC(inited_cpus);

  if (smp_info->lapic_id != bsp_lapic_id)
    sched_await();

  return;
}

int init_smp(struct stivale2_struct_tag_smp *smp_info) {
  bsp_lapic_id = smp_info->bsp_lapic_id;
  cpu_locals = kmalloc(sizeof(cpu_locals_t) * smp_info->cpu_count);

  for (size_t i = 0; i < smp_info->cpu_count; i++) {
    cpu_locals[i].cpu_number = i;

    LOCKED_WRITE(smp_info->smp_info[i].extra_argument,
                 (uint64_t)&cpu_locals[i]);

    if (smp_info->smp_info[i].lapic_id == bsp_lapic_id) {
      smp_init_cpu(&smp_info->smp_info[i]);
      continue;
    }

    LOCKED_WRITE(smp_info->smp_info[i].target_stack,
                 (uint64_t)pcalloc(1) + PHYS_MEM_OFFSET + PAGE_SIZE);
    LOCKED_WRITE(smp_info->smp_info[i].goto_address, (uint64_t)smp_init_cpu);
  }

  while (LOCKED_READ(inited_cpus) != smp_info->cpu_count)
    ;

  return 0;
}
