#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>


// the socks client send request to server to ensure the version and auth method
// the format of this packet :
/*
    +--------------------------+
    | ver | nmethods | methods |
    +=====+==========+=========+
    |  1B |    1B    | 1-255 B |
    +--------------------------+

    ver : socks version
    nmethods : number of methods 
    methods : support auth method, one method one byte, variable from 1-255
*/ 

enum SOCKS_VERSION{
    VERSION_RESERVED = 0x00,
    VERSION_4 = 0x04,
    VERSION_5 = 0x05,
};

enum SOCKS_AUTH_STATUS{
    AUTH_SUCCESS = 0x00,
    AUTH_FAIL = 0x01
};

// Record the methods supported by socks 5
enum SOCKS_AUTH_METHODS{
    AUTHM_NOAUTH = 0x00,    // no auth
    AUTHM_GSSAPI = 0x01,    // gssapi auth
    AUTHM_USERPASS = 0x02,  // username and password auth

    AUTHM_IANA_RESERVED_START = 0x03, // 0x03->0x7f, reserved for iana
    AUTHM_IANA_RESERVED_END = 0x7f,

    AUTHM_PRIVATE_RESERVED_START = 0x80, // 0x80->0xfe, reserved for private methods
    AUTHM_PRIVATE_RESERVED_END = 0xfe,

    AUTHM_NOMETHOD = 0xff, // cannot support this method
};

// Then the server will chose an auth method 
// and then response the following packet
/**
 * +==============+
 * | VER | Method |
 * +==============+
 * |  1  |    1   |
 * +==============+
*/


// Server and Client can auth each other by this method

// After auth, client can send request, request format : 
/**
 * +-----------------------------------+
 * 
*/
// And the server response format
/**
 * 
 * 
 * 
*/

// the command of sock server
enum SOCK_REQUEST_CMD{
    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,
    CMD_UDP = 0x03
};

enum SOCK_RESPONSE_REP{
    REP_SUCCESS = 0x00,
    REP_FAIL = 0x01,
    REP_DISALLOW = 0x02,
    REP_NETWORK_UNREACHABLE = 0x03,
    REP_HOST_UNREACHABLE = 0x04,
    REP_REJECT = 0x05,
    REP_TTLTIMEOUT = 0x06,
    REP_UNSUPPORTCMD = 0x07,
    REP_UNSUPPORTADDR = 0x08,
    REP_UNDEFINE_START = 0x09,
    REP_UNDEFINE_END = 0xFF
};

enum SOCK_ATYP_TYPE{
    ATYP_IPV4 = 0x01,
    ATYP_DOMAIN = 0x03,
    ATYP_IPV6 = 0x04
};

