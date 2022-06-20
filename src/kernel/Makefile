include ../../config.mk

LD = ../../cross/bin/x86_64-elf-ld
CC = ../../cross/bin/x86_64-elf-gcc
AS = nasm

KERNEL =../../build/kernel/mandelbrotos.elf

CFLAGS := $(CFLAGS) \
	-mcmodel=kernel \
	-ffreestanding \
	-I./include \
	-mno-red-zone \
	-mgeneral-regs-only \
	-fno-pic -no-pie \
	-fno-stack-protector \
	-Wno-implicit-fallthrough \
	-Wno-error=unused-parameter

LDFLAGS := \
	-static \
	-T../../resources/linker.ld \
	-nostdlib \
	-z max-page-size=0x1000

CFILES := $(shell find ./ -name '*.c')
ASFILES := $(shell find ./ -name '*.asm')

OBJ = $(patsubst %.c, $(KERNEL_BUILD_DIRECTORY)/%.c.o, $(CFILES)) \
        $(patsubst %.asm, $(KERNEL_BUILD_DIRECTORY)/%.asm.o, $(ASFILES))

KERNEL_DIRECTORY_GUARD = mkdir -p $(@D)

all: $(KERNEL)

$(KERNEL): $(OBJ)
	@ echo "[LD] $^"
	@ $(LD) $(LDFLAGS) $^ -o $@

$(KERNEL_BUILD_DIRECTORY)/%.c.o: %.c
	@ echo "[CC] $^"	
	@ $(KERNEL_DIRECTORY_GUARD)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_BUILD_DIRECTORY)/%.asm.o: %.asm
	@ echo "[AS] $^"
	@ $(KERNEL_DIRECTORY_GUARD)
	@ $(AS) $(ASFLAGS) $< -o $@
