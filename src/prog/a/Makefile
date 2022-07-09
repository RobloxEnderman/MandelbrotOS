include ../../../config.mk

LD = ../../../cross/bin/x86_64-elf-ld
CC = ../../../cross/bin/x86_64-elf-gcc
AS = nasm

CFLAGS := $(CFLAGS) \
	-Isrc/include \
	-I../../libc/src/include \
	-ffreestanding \
	-mno-red-zone \
	-fno-pic -no-pie \
	-static \

ASFLAGS := $(ASFLAGS) \
	-static \

LDFLAGS := \
	-Tlinker.ld \
	-L../../../build/libc \

CFILES := $(shell find src/ -name '*.c')
ASFILES := $(shell find src/ -name '*.asm')
OFILES := $(CFILES:.c=.o) $(ASFILES:.asm=.o)

TARGET = ../../../build/prog/a

all: clean compile

compile: ld
	@ echo "Done!"
	
ld: $(OFILES)
	@ echo "[LD] $^"
	@ $(LD) $(LDFLAGS) $^ -lc -o $(TARGET)

%.o: %.c
	@ echo "[CC] $<"
	@ $(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	@ echo "[AS] $<"
	@ $(AS) $(ASFLAGS) $< -o $@

clean:
	@ echo "[CLEAN]"
	@ rm -rf $(OFILES) $(TARGET)
