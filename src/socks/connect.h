#ifndef _H_CONNECT
#define _H_CONNECT
#define _GNU_SOURCE
#include "socks_pack.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/types.h>
#include <netinet/tcp.h>
#include <unistd.h>

#define CONNECT_FORMAT_ERROR -1
#define CONNECT_HOST_ERROR -2
#define CONNECT_REJECT_ERROR -3


/*======================================================*/
/*                                                      */
/*============= Connection Issue =======================*/
/*                                                      */
/*======================================================*/

// handle the socks address type
// set the addr buffer appropriate format
// original buf : 
//          ipv4 -> XXXX
//          ipv6 -> XXXX XXXX XXXX XXXX
//          domain -> (len byte(1B)) XXXXXX(variable len)
// Trans to this format:
//          ipv4 -> XXXX
//          ipv6 -> XXXX
//          domain -> XXXXXX '\0'
static void _socks5_setaddr_ipv4(char *addrbuf);
static void _socks5_setaddr_ipv6(char *addrbuf);
static void _socks5_setaddr_domain(char *addrbuf);

// connect method for diffrent addr type
// return the connection fd
static int _socks5_connect_ipv4(char *addrbuf,unsigned short port);
static int _socks5_connect_ipv6(char *addrbuf, unsigned short port);
static int _socks5_connect_domain(char *addrbuf, unsigned short port);

// handle the socks connect by diffrent addr type
// return the connection fd
int socks5_handle_connection(unsigned char addr_type, char *addrbuf, unsigned short port);

static int _socks5_sockudp_ipv6(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr);
static int _socks5_sockudp_ipv4(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr);
static int _socks5_sockudp_domain(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr);
int socks5_handle_udpsock(unsigned char addrtype, char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr);

#endif