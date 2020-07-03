#ifndef _H_UTILS
#define _H_UTILS
#include <errno.h>
#include <unistd.h>

int readn(int fd, void *buf, int n);
int writen(int fd, void *buf, int n);

#endif