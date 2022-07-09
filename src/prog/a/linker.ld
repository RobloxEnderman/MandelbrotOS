OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS
{
  . = 4M;

  .text : ALIGN(4K) {
    *(.text)
  }

  .data : ALIGN(4K) {
    *(.data)
  }

  .bss : ALIGN(4K) {
    *(COMMON)
    *(.bss)
  }
  
  .rodata : ALIGN(4K) {
    *(.rodata)
  }

  .eh_frame : ALIGN(4K) {
    *(.eh_frame)
  }
}
