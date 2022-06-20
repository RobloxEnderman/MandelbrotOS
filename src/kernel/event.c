#include <event.h>
#include <lock.h>
#include <stddef.h>

int event_await(event_t **events, size_t count, int block) {
  for (size_t i = 0; i < count; i++)
    LOCK(events[i]->lock);

  for (size_t i = 0; i < count; i++)
    if (LOCKED_READ(events[i]->pending)) {
      events[i]->pending--;
      return i;
    }

  for (size_t i = 0; i < count; i++)
    UNLOCK(events[i]->lock);

  if (!block)
    return -1;

  while (1)
    for (size_t i = 0; i < count; i++)
      if (LOCKED_READ(events[i]->pending)) {
        events[i]->pending--;
        return i;
      }
}

void event_trigger(event_t *event) {
  LOCK(event->lock);
  LOCKED_INC(event->pending);
  UNLOCK(event->lock);
}
