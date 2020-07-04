#ifndef _H_SOCKS_PACK
#define _H_SOCKS_PACK

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../utils/utils.h"

/*=========================== PREDEFINED VALUE ==============*/
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

// Then the server will chose an auth method 
// and then response the following packet
/**
 * +==============+
 * | VER | Method |
 * +==============+
 * |  1  |    1   |
 * +==============+
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

// After auth, client can send request, request format : 
/**
 * +----------------------------------------------+
 * | Ver | Cmd | Rsv | ATYP | DST.ADDR | DST.PORT |
 * +----------------------------------------------+
 * |  1  |  1  |  1  |   1  |  Var     |    2     |
 * +----------------------------------------------+
 * 
 * ver : socks version, here is socks5
 * cmd : sock command
 * RSV : keep 0x00 now, it's reserved
 * Atyp : type of dst.addr, can be domain/ipv4/ipv6
 * port : port of dst (in network byte order)
 * 
*/
// And the server response format
/**
 * +------------------------------------------------+
 * | ver | rep | rsv | atyp | bind.addr | bind.port |
 * +------------------------------------------------+
 * |  1  |  1  |  1  | atyp |   Var     |   2       |
 * +------------------------------------------------+
 * 
 * rep : response code to inform the sock status
 * 
 * BIND : the bind mode is used in protocols which require the client
 *        to recv conn from the server
 * bind_addr : 
*/

// the command of sock server
enum SOCK_REQUEST_CMD{
    CMD_CONNECT = 0x01,
    CMD_BIND = 0x02,
    CMD_UDP = 0x03
};

// to inform the handle result
enum SOCK_HANDLE_STATUS{
    HANDLE_FORMAT_SUCCESS = 0x00,
    HANDLE_FORMAT_FAIL = 0x01,
    HANDLE_SUCCESS = 0x02,
    HANDLE_FAIL = 0x03
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

typedef struct SOCKS5_REQUEST_PACK* Socks5RequestPacket;
typedef struct SOCKS5_RESPONSE_PACK* Socks5ResponsePacket;

// =========== request packet ===============
Socks5RequestPacket  init_socks5_request_pack(void);
Socks5RequestPacket  make_socks5_request_from_fd(int fd);
void free_socks5_request_pack(Socks5RequestPacket packet);
// define getter and setter
unsigned char get_version_socks5req(Socks5RequestPacket packet);
unsigned char get_cmd_socks5req(Socks5RequestPacket packet);
unsigned char get_atype_socks5req(Socks5RequestPacket packet);
unsigned short get_port_socks5req(Socks5RequestPacket packet);
char *get_addr_socks5req(Socks5RequestPacket packet);


// =========== response packet ===============
Socks5ResponsePacket init_socks5_response_pack(void);
Socks5ResponsePacket make_socks5_response_pack(unsigned char rep_code, unsigned char atype, char *addr, unsigned short port);

unsigned char send_socks5_response_to_fd(Socks5ResponsePacket packet, int fd);
void free_socks5_response_pack(Socks5ResponsePacket packet);
// define getter and setter
void set_version_socks5res(Socks5ResponsePacket packet, unsigned char version);
void set_rep_socks5res(Socks5ResponsePacket packet, unsigned char rep);
void set_atype_socks5res(Socks5ResponsePacket packet, unsigned char atype);
void set_port_socks5res(Socks5ResponsePacket packet, unsigned short port);
void set_addr_socks5res(Socks5ResponsePacket packet, char *addr);




#endif