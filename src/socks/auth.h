#ifndef _H_SOCKS_AUTH
#define _H_SOCKS_AUTH

#define AUTH_FORMAT_ERR 0x00
#define AUTH_FORMAT_SUC 0x01

#include "../utils/utils.h"
#include <string.h>
#include "socks_pack.h"

/*================= Functions ========================*/

// read bytes from fd, and return the auth_status
// will called by socks5_handler in its thread
// args : sock fd 
// return : the result of auth
unsigned char socks5_auth(void *fd);

// parse packet and extract data from raw binary data
// but will not deal with the auth
// A private function
// args : 
//         int -- sock fd
//         char* -- num of methods
//         char* -- version of sock
//         char* -- buffer bigger than 256 Bytes
// return : 
//         AUTH_FORMAT_ERR / AUTH_FORMAT_SUC
unsigned char static _socks5_parse_auth(int fd, char *nmethods, char *version,char *buffer);

// Chose an auth  method for client
// args  : buffer of support method, and number of methods
// return : A method code
static unsigned char _socks5_chose_method(unsigned char nmethods, char *buffer);

// Construct Auth method Info Response to client and send
// args : unsigned char method_code 
// return : void
void _socks5_method_response(int fd, unsigned char method_code);

// Call the specified method to auth
// args : method code, sock fd
// return : auth result
static unsigned char _socks5_auth_dispatch(int fd, unsigned char method_code);

// An example of auth method--username / password method
// args : sock fd
// return : AUTH_SUCCESS / AUTH_FAIL
static unsigned char _auth_userpass(int fd);

// inner functions of userpass
unsigned char _auth_userpass_getpass(char *username, char *passbuf);

#endif 