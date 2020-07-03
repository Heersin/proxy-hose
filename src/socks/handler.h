#ifndef _H_HANDLER
#define _H_HANDLER
#define _GNU_SOURCE

#include "../utils/utils.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/types.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "socks_pack.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))


// handle client request first
unsigned char socks5_handle(void *fd);

// extract data from raw packet
// and check its format
// args : fd, version_ptr, type_code_ptr, addr_buffer, port_ptr
//         addr_buffer [>128]
//         port_buff[2]
// return : HANDLE_FORMAT_SUCCESS/HANDLE_FORMAT_FAIL

// Deprecated , a new version
// static unsigned char _socks5_parse_request(int fd, char *version, char *cmd, char *type_code,char *addrlen, char *addrbuf, char *port_buf);
//static unsigned char _socks5_make_response(int fd, unsigned char version, unsigned char rep, unsigned char addrtype, unsigned char addr_len, char *addrbuf, char *portbuf);


/*======================================================*/
/*                                                      */
/*==================== CMD Issue =======================*/
/*                                                      */
/*======================================================*/
// handle the socks cmd, call the specified function
// to handle diffrent cmd
// return : HANDLE_SUCCESS/HANDLE_FAIL
static unsigned char _socks5_handle_cmd(int fd, Socks5RequestPacket request);

// diffrent command
static unsigned char _socks5_cmd_bind(int fd, char *addrbuf, char *port);
static unsigned char _socks5_cmd_connect(int fd, char *addrbuf, char *port);
static unsigned char _socks5_cmd_udp(int fd, char *addrbuf, char *port);

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
static int _socks5_connect_ipv4(char *addrbuf, char *port);
static int _socks5_connect_ipv6(char *addrbuf, char *port);
static int _socks5_connect_domain(char *addrbuf, char *port);

// handle the socks connect by diffrent addr type
// return the connection fd
static int _socks5_handle_connection(unsigned char addr_type, char *addrbuf, char *port);

/*======================================================*/
/*                                                      */
/*================ Transfer Issue ======================*/
/*                                                      */
/*======================================================*/
// passing data
static unsigned char _socks5_handle_transfer(int fd, char *databuf);


#endif