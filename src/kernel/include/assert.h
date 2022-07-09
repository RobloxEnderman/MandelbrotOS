#ifndef __ASSERT_H__
#define __ASSERT_H__

#include <printf.h>

#define assert(expr)                                                           \
  if (!(expr)) {                                                               \
    printf("Assertion \"%s\" on line %lu, file %s failed!\n", #expr, __LINE__, \
           __FILE__);                                                          \
    while (1) {                                                                \
      asm volatile("cli");                                                     \
      asm volatile("hlt");                                                     \
    }                                                                          \
  }

#endif
