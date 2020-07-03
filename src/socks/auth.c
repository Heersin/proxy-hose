#include "auth.h"

// implemented auth methods
static unsigned char INNER_METHODS[256] = {
    // 64
    AUTHM_USERPASS, AUTHM_NOAUTH, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 128
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 192
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 256
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static int INNER_METHOD_NUM = 2;

unsigned char socks5_auth(void *fd)
{
    unsigned char version;
    unsigned char nmethod;
    unsigned char *methods_buffer[256];
    unsigned char method;

    unsigned char process_result;

    // init
    version = VERSION_5;
    method = AUTHM_NOMETHOD;

    // get info from client
    process_result =  _socks5_parse_auth(fd, &nmethod, &version, methods_buffer);
    if (process_result == AUTH_FORMAT_ERR)
        return AUTH_FAIL;
    
    // chose a proper method
    method = _socks5_chose_method(nmethod, methods_buffer);

    // make a response to client
    _socks5_method_response(fd, method);

    // dispatch to handle diffrent ways of auth
    process_result =  _socks5_auth_dispatch(fd, method);
    if (process_result == AUTH_FAIL)
        return AUTH_FAIL;
    
    return AUTH_SUCCESS;
}

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
unsigned char static _socks5_parse_auth(int fd, char *nmethods, char *version,char *buffer)
{
    readn(fd, version, 1);
    readn(fd, nmethods, 1);
    
    unsigned char number;
    unsigned char tmp;

    number = (unsigned char) *nmethods;
    // check the number of methods
    if( number == 0x00)
        return AUTH_FORMAT_ERR;
    
    // read methods
    readn(fd, buffer, number);

    return AUTH_FORMAT_SUC;
}

// Chose an auth  method for client
// args  : buffer of support method, and number of methods
// return : A method code
static unsigned char _socks5_chose_method(unsigned char nmethods, char *buffer)
{
    // the RFC requires socks server chose an auth method
    // By Greedy algorithm, due to the small scale of auth methods
    // we can arrange methods in a proper order to fit "Greedy"
    // with simple for loop search

    // Arrange Auth Methods from high security to low in init procedure

    int tmp;
    int tmp2;
    unsigned char current_method;
    unsigned char client_method;
    
    for(tmp = 0; tmp < INNER_METHOD_NUM; tmp++){
        current_method = INNER_METHODS[tmp];
        for(tmp2 = 0; tmp2 < nmethods; ++tmp2){
            client_method = buffer[tmp2];
            // find one match method, it's the highest secure one
            if(client_method == current_method)
                return client_method;
        }

        // no match method, try next server method, the lower security method
        if(tmp2 == nmethods){
            continue;
        }
    }

    // oh , no more server method for auth
    return AUTHM_NOMETHOD;
}

// Construct Auth method Info Response to client and send
// args : unsigned char method_code 
// return : void
void _socks5_method_response(int fd, unsigned char method_code)
{
    unsigned char version = 0x01;
    writen(fd, &method_code, 1);
    writen(fd, &method_code, 1);
}

// Call the specified method to auth
// args : method code, sock fd
// return : auth result
static unsigned char _socks5_auth_dispatch(int fd, unsigned char method_code)
{
    switch (method_code)
    {
    case AUTHM_NOAUTH:
        /* code */
        return AUTH_SUCCESS;
        break;

    case AUTHM_GSSAPI:
        // not implement
        return AUTH_FAIL;
        break;

    case AUTHM_USERPASS:
        return _auth_userpass(fd);
        break;
        
    default:
        return AUTH_FAIL;
        break;
    }
}

// An example of auth method--username / password method
// args : username, password
// return : AUTH_SUCCESS / AUTH_FAIL
static unsigned char _auth_userpass(int fd)
{
    char password[128];

    char request_user[128];
    char request_pass[128];
    unsigned char request_user_len;
    unsigned char request_pass_len;
    unsigned char version;

    unsigned char auth_result;

    // get username from auth request;
    // +==========================================+
    // | ver | user_len | user | pass_len | pass |
    // +==========================================+
    // |  1  |    1     |  Var |    1     |  Var |
    // +==========================================+

    // version is 0x01 now
    // vulnrable -- set a len > 128 to overflow it XD
    // its a backdoor
    readn(fd,&version, 1);
    readn(fd,&request_user_len,1);
    readn(fd,&request_user, request_user_len);
    readn(fd,&request_pass_len, 1);
    readn(fd,&request_pass, request_pass_len);

    // get password by username
    auth_result = _auth_userpass_getpass(request_user, password);
    if(auth_result == AUTH_FAIL){
        // not found username
        return auth_result;
    }

    // compare with password from request
    if (strcmp(request_pass, password) == 0)
        auth_result = AUTH_SUCCESS;
    else
        auth_result = AUTH_FAIL;
    
    // write answer for response
    writen(fd, &version, 1);
    writen(fd, &auth_result, 1);

    
    return auth_result;
}

// inner functions of userpass
unsigned char _auth_userpass_getpass(char *username, char *passbuf)
{
    if(username == NULL)
        return AUTH_FAIL;
    
    int i;
    // 0123456789 - 10 chars
    for (i = 0; i < 10; ++i){
        passbuf[i] = '0' + i;
    }

    return AUTH_SUCCESS;
}