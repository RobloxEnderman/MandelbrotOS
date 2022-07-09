#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mandelbrot.h>
#include <sys/mman.h>
#include <unistd.h>

#define ABS(x) ((x < 0) ? (-x) : x)

uint16_t width;
uint16_t height;
uint32_t *framebuffer;

uint64_t intsyscall(uint64_t id, uint64_t arg1, uint64_t arg2, uint64_t arg3,
                    uint64_t arg4, uint64_t arg5);

int main() {
  printf("Hello, world!\n");
  return 9;
}
