#include "utils.h"

GLOBAL_MODE_FLAGS = 0x00;

int readn(int fd, void *buf, int n)
{
	int nread, left = n;
	while (left > 0) {
		if ((nread = read(fd, buf, left)) == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
		} else {
			if (nread == 0) {
				return 0;
			} else {
				left -= nread;
				buf += nread;
			}
		}
	}
	return n;
}

int writen(int fd, void *buf, int n)
{
	int nwrite, left = n;
	while (left > 0) {
		if ((nwrite = write(fd, buf, left)) == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
		} else {
			if (nwrite == n) {
				return 0;
			} else {
				left -= nwrite;
				buf += nwrite;
			}
		}
	}
	return n;
}

unsigned short split_addr_port(malloc_string addrport, char **bind_addr_ptr)
{
	unsigned short port;
	malloc_string addr;
	int addr_len;
	char *split;

	split = strchr(addrport, ':');
	addr_len = (int)(addrport - split);

	// set addr
	addr = (malloc_string)malloc(addr_len + 1);
	addr[addr_len] = '\0';
	strncpy(addr, addrport, addr_len);

	// get port num
	port = (unsigned short)atoi(split + 1);

	// return 
	*bind_addr_ptr = addr;
	return port;
}