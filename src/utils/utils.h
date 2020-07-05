#ifndef _H_UTILS
#define _H_UTILS
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#define TRUE 0x01
#define FLASE 0x00

// MACRO, 8 FLAGS AT MOST
#define GLOBAL_FLAG_AS_RELAY 0x01
#define GLOBAL_FLAG_SOCKS 0x02
#define GLOBAL_FLAG_HTTP 0x04
// reserved ~

// For command Line to set flag
unsigned char GLOBAL_MODE_FLAGS;

// some utils to detect FLAG
int is_as_relay_server();
int set_as_relay_server();


int readn(int fd, void *buf, int n);
int writen(int fd, void *buf, int n);


// need to free
typedef char *malloc_string;

// tricky but bad way I think
unsigned short split_addr_port(malloc_string addrport, char **bind_addr_ptr);

#endif