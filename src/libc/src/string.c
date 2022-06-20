#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *sys_siglist[] = {
  [SIGHUP] = "Hangup",
  [SIGINT] = "Interrupt",
  [SIGQUIT] = "Quit",
  [SIGILL] = "Illegal instruction",
  [SIGTRAP] = "Trace/breakpoint trap",
  [SIGABRT] = "Aborted",
  [SIGEMT] = "Emulation trap",
  [SIGFPE] = "Arithmetic exception",
  [SIGKILL] = "Killed",
  [SIGBUS] = "Bus error",
  [SIGSEGV] = "Segmentation fault",
  [SIGSYS] = "Bad system call",
  [SIGPIPE] = "Broken pipe",
  [SIGALRM] = "Alarm clock",
  [SIGTERM] = "Terminated",
  [SIGUSR1] = "User defined signal 1",
  [SIGUSR2] = "User defined signal 2",
  [SIGCHLD] = "Child status changed",
  [SIGPWR] = "Power fail/restart",
  [SIGWINCH] = "Window size changed",
  [SIGURG] = "Urgent I/O condition",
  [SIGPOLL] = "Pollable event occurred",
  [SIGSTOP] = "Stopped (signal)",
  [SIGTSTP] = "Stopped (user)",
  [SIGCONT] = "Continued",
  [SIGTTIN] = "Stopped (tty input)",
  [SIGTTOUT] = "Stopped (tty input)",
  [SIGVTALRM] = "Virtual timer expired",
  [SIGPROF] = "Profiling timer expired",
  [SIGXCPU] = "CPU time limit exceeded",
  [SIGXFSZ] = "File size limit exceeded",
};

char *strchr(char *str, int c) {
  for (; *str && *str != c; str++)
    ;
  return (*str) ? str : (c) ? NULL : str;
}

size_t strlen(char *s) {
  size_t i;
  for (i = 0; s[i] != '\0'; i++)
    ;
  return i;
}

void memcpy(void *dest, void *src, size_t n) {
  for (size_t i = 0; i < n; i++)
    ((char *)dest)[i] = ((char *)src)[i];
}

char *strdup(char *s) {
  char *str = malloc(strlen(s) + 1);
  memcpy(str, s, strlen(s) + 1);
  return str;
}

int strncmp(char *_l, char *_r, size_t n) {
  uint8_t *l = (void *)_l;
  uint8_t *r = (void *)_r;
  if (!n--)
    return 0;
  for (; *l && *r && n && *l == *r; l++, r++, n--)
    ;
  return *l - *r;
}

void strcat(char *dest, char *src) {
  while (*dest)
    dest++;
  while ((*dest++ = *src++))
    ;
}

void *memset(void *buf, char val, size_t len) {
  while (len--)
    ((char *)buf)[len] = val;
  return buf;
}

char *strcpy(char *dest, char *src) {
  char *temp = dest;
  while ((*dest++ = *src++))
    ;
  return temp;
}

char *strncpy(char *dest, char *src, size_t n) {
  char *temp = dest;
  while (*src && n--)
    *dest++ = *src++;
  *dest = '\0';
  return temp;
}

size_t strspn(char *cs, char *ct) {
  size_t n;
  char *p;
  for (n = 0; *cs; cs++, n++) {
    for (p = ct; *p && *p != *cs; p++)
      ;
    if (!*p)
      break;
  }
  return n;
}

size_t strcspn(char *cs, char *ct) {
  size_t n;
  char *p;
  for (n = 0; *cs; cs++, n++) {
    for (p = ct; *p && *p == *cs; p++)
      ;
    if (!*p)
      break;
  }
  return n;
}

char *strpbrk(char *s, char *b) {
  s += strcspn(s, b);
  return *s ? (char *)s : NULL;
}

char *strsignal(int sig) {
  if (sig < 0 || sig > 31)
    return NULL;
  return sys_siglist[sig];
}
