#ifndef __WAIT_H__
#define __WAIT_H__

#include <sys/types.h>

#define WNOHANG 1
#define WUNTRACED 2

#define WEXITSTATUS(x) ((x)&0x000000FF)
#define WIFEXITED(x) ((x)&0x00000200)
#define WIFSIGNALED(x) ((x)&0x00000400)
#define WTERMSIG(x) (((x)&0xFF000000) >> 24)

pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);

#endif
