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
#include "connect.h"
#include "socks_relay.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))


// handle client request first
unsigned char socks5_handle(void *fd);

// extract data from raw packet
// and check its format
// args : fd, version_ptr, type_code_ptr, addr_buffer, port_ptr
//         addr_buffer [>128]
//         port_buff[2]
// return : HANDLE_FORMAT_SUCCESS/HANDLE_FORMAT_FAIL

// Deprecated , a new version as struct method
// static unsigned char _socks5_parse_request(int fd, char *version, char *cmd, char *type_code,char *addrlen, char *addrbuf, char *port_buf);
// static unsigned char _socks5_make_response(int fd, unsigned char version, unsigned char rep, unsigned char addrtype, unsigned char addr_len, char *addrbuf, char *portbuf);


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
static unsigned char _socks5_cmd_connect(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd);
static unsigned char _socks5_cmd_bind(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd);
static unsigned char _socks5_cmd_udp(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd);




// return a string contains addr and port
// Format : addr:port
// Example : 127.0.0.1:8080
// default path : ~/.phose_cfg.conf
static malloc_string _load_relay_server_config(char *config);

#endif