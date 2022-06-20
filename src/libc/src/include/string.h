#ifndef __STRING_H__
#define __STRING_H__

#include <stddef.h>

extern char *sys_siglist[];

char *strchr(char *str, int c);
size_t strlen(char *s);
void memcpy(void *dest, void *src, size_t n);
char *strdup(char *s1);
int strncmp(char *s1, char *s2, size_t n);
void strcat(char *dest, char *src);
void *memset(void *buf, char val, size_t len);
char *strcpy(char *dest, char *src);
char *strncpy(char *dest, char *src, size_t n);
char *strpbrk(char *s, char *b);
char *strsignal(int sig);

#endif
