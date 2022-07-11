#include <fs/vfs.h>
#include <mm/kheap.h>
#include <pipe/pipe.h>
#include <printf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int pipe_init(pipe_t *pipe, size_t capacity) {
  if (!pipe)
    return 1;
  pipe->buffer = kcalloc(capacity * sizeof(char *));
  pipe->buffer_end = (char *)pipe->buffer + capacity * sizeof(char *);
  pipe->head = pipe->buffer;
  pipe->tail = pipe->buffer;

  return 0;
}

void pipe_free(pipe_t *pipe) { kfree(pipe->buffer); }

ssize_t pipe_write(pipe_t *pipe, uint8_t *item, size_t count) {
  if (pipe->head + count >= pipe->buffer_end)
    return 0;
  memcpy(pipe->head, item, count);
  pipe->head += count;
  if (pipe->head >= pipe->buffer_end)
    pipe->head = pipe->buffer;
  return count;
}

ssize_t pipe_read(pipe_t *pipe, uint8_t *item, size_t count) {
  size_t read = 0;
  if (pipe->tail >= pipe->head)
    return -1;
  while (count--) {
    item[read] = pipe->tail[read];
    read++;
    if (pipe->tail >= pipe->head)
      return -1;
  }
  pipe->tail += read;
  if (pipe->tail >= pipe->buffer_end)
    pipe->tail = pipe->buffer;
  return read;
}
