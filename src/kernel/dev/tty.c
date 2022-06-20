#include <dev/device.h>
#include <dev/tty.h>
#include <drivers/ps2.h>
#include <fb/fb.h>
#include <fs/vfs.h>
#include <lock.h>
#include <mm/kheap.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

ssize_t tty_write(device_t *dev, size_t start, size_t count, uint8_t *buf) {
  (void)start;
  (void)dev;
  for (size_t i = 0; i < count; i++)
    putchar(buf[i]);
  return count;
}

ssize_t tty_read(device_t *dev, size_t start, size_t count, uint8_t *buf) {
  (void)dev;
  (void)start;
  (void)buf;

  size_t init_count = count;
  while (count) {
    char c = getchar();
    putchar(c);
    buf[init_count - count] = c;
    count--;
    if (c == '\n')
      break;
  }

  buf[init_count - count + 1] = 0;

  return init_count - count;
}

static device_t tty0 = (device_t){
  .block_count = 0,
  .block_size = 0,
  .fs = NULL,
  .id = 100,
  .name = "tty0",
  .private_data = NULL,
  .read = tty_read,
  .write = tty_write,
  .type = S_IFCHR,
};

int init_tty(char *mount_place) {
  char *str = kcalloc(strlen(mount_place) + 7);
  strcpy(str, mount_place);

  if (str[strlen(str) - 1] != '/')
    str[strlen(str)] = '/';

  strcat(str, "tty0");

  device_add(&tty0);

  int val = (vfs_mknod(str, 0777 | S_IFCHR, 0, 0, &tty0)) ? 0 : 1;
  kfree(str);
  return val;
}
