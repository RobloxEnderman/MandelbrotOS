HDD = mandelbrotos.hdd

QEMU = qemu-system-x86_64 -hdd $(HDD) -smp 2 -M q35 -soundhw pcspk -serial stdio -rtc base=localtime -enable-kvm
# QEMU = qemu-system-x86_64 -hdd $(HDD) -smp 1 -M q35 -soundhw pcspk -monitor stdio -d int -rtc base=localtime

KERNEL = build/kernel/mandelbrotos.elf

BUILD_DIRECTORY = build
KERNEL_BUILD_DIRECTORY := ../../build/kernel/
PROG_BUILD_DIRECTORY := ../../build/prog/
DIRECTORY_GUARD = mkdir -p build/

OPTIMISATION = -O3
# OPTIMISATION = -g

ASFLAGS = -f elf64 $(OPTIMISATION) -static

CFLAGS := \
	-Werror \
	-Wall \
	-Wextra \
	-std=gnu99 \
	$(OPTIMISATION) \
	-pipe \
