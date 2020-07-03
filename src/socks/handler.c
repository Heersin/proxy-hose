#include "handler.h"

// handle client request first
unsigned char socks5_handle(void *fd)
{
    unsigned char version;
    unsigned char typecode;
    unsigned char cmdcode;
    unsigned char addr_len;

    unsigned char addr_buf[129];
    unsigned char port_buf[2];

    unsigned char handle_result;
    handle_result = HANDLE_FAIL;

    // new version with struct
    Socks5RequestPacket request = NULL;
    Socks5ResponsePacket response = NULL;

    // parse request and store in our struct
    request = make_socks5_request_from_fd((int)fd);
    
    // if failed, response and return
    if(request == NULL)
    {
        response = init_socks5_response_pack();
        set_rep_socks5res(response, REP_UNSUPPORTADDR);
        send_socks5_response_to_fd(response, (int)fd);
        free_socks5_response_pack(response);
        return HANDLE_FORMAT_FAIL;
    }

    // handle different command here
    // client ----request----> server ( Handle Request ) 
    // client <---response---- server ( Make Response )
    handle_result = _socks5_handle_cmd((int)fd, request);


    return handle_result;
}

// extract data from raw packet
// and check its format
// args : fd, version_ptr, type_code_ptr, addr_buffer, port_ptr
//         addr_buffer [>128]
//         port_buff[2]
// return : HANDLE_FORMAT_SUCCESS/HANDLE_FORMAT_FAIL
static unsigned char _socks5_parse_request(int fd, char *version, char *cmd, char *type_code, char *addrlen, char *addrbuf, char *port_buf)
{
    unsigned char rsv;
    unsigned char len;
    readn(fd, version, 1);
    readn(fd, cmd, 1);
    readn(fd, &rsv, 1);
    readn(fd, type_code, 1);

    rsv = (unsigned char)*type_code;

    switch (rsv)
    {
    case ATYP_IPV4:
        len = 4;
        break;
    case ATYP_IPV6:
        len = 16;
        break;
    case ATYP_DOMAIN:
        // WARNING : buf overflow may happend here
        // set a number bigger than 128(it's possible due to the byte is 0-255)
        // later we will read len bytes, but len is bigger than 128
        // so it can overflow the addr_buf
        // another backdoor
        readn(fd, addrlen, 1);
        len = (unsigned char) *addrlen;
        break;
    default:
        // error ?
        return HANDLE_FORMAT_FAIL;
        break;
    }

    readn(fd, addrbuf, len);
    readn(fd, port_buf, 2);

    return HANDLE_FORMAT_SUCCESS;
}
static unsigned char _socks5_make_response(int fd, unsigned char version, unsigned char rep, unsigned char addrtype, unsigned char addr_len, char *addrbuf, char *portbuf)
{
    unsigned char rsv;
    rsv = 0x00;

    unsigned char fail[10];

    switch (rep)
    {
        // success state
        // there should have been a malloc to create array 
        // store these data and send together
        // but I keep it simple now
    case REP_SUCCESS:
        writen(fd, &version, 1);
        writen(fd, &rep, 1);
        writen(fd, &rsv, 1);
        writen(fd, &addrtype, 1);
        writen(fd, addrbuf, addr_len);
        writen(fd, portbuf, 2);
        break;

        // fail state, just fall through 
    case REP_FAIL:
    case REP_DISALLOW:
    case REP_NETWORK_UNREACHABLE:
    case REP_HOST_UNREACHABLE:
    case REP_REJECT:
    case REP_TTLTIMEOUT:
    case REP_UNSUPPORTCMD:
    case REP_UNSUPPORTADDR:
    default:
        fail[0] = 0x05;  // version
        fail[1] = rep;   // rep
        fail[2] = rsv;
        fail[3] = 0x01;  // just keep it as IPV4
        fail[4] = 0x00;fail[5] = 0x00;fail[6] = 0x00; fail[7] = 0x00;
        fail[8] = 0x00;fail[9] = 0x00;

        // WARNING:This is riskful
        // Because the client program may check the response
        // The Addr Type in our response may conflict with client request
        // so it's possible that client would throw it or just crash~
        writen(fd, fail, 10);
        break;
    }
    return HANDLE_SUCCESS;
}


// handle the socks cmd, call the specified function
// to handle diffrent cmd
// return : HANDLE RESULT
static unsigned char _socks5_handle_cmd(int fd, Socks5RequestPacket request)
{
    unsigned char rep_code;
    switch (cmd_code)
    {
    case CMD_CONNECT:
        rep_code = _socks5_cmd_connect(fd, addrbuf, portbuf);
        break;
    
    case CMD_BIND:
        rep_code = _socks5_cmd_bind(fd, addrbuf, portbuf);
        break;
    
    case CMD_UDP:
        rep_code = _socks5_cmd_udp(fd, addrbuf, portbuf);
        break;

    default:
        // error ?
        rep_code = REP_UNSUPPORTCMD;
        break;
    }

    // make response to tell the client the addres of our relay server
    // typecode can be easily set as ipv4 format/domain format
    // TODO: change typecode / addrlen / addrbuf / portbuf
    //       relay server can be read from config
    _socks5_make_response(fd, 0x05, rep_code, typecode, addrlen, addrbuf, portbuf);


    // if rep is fail, then inform our socks server that the handle procedure is failed
    if(rep_code != REP_SUCCESS)
        return HANDLE_FAIL;
    else
        return HANDLE_SUCCESS;
}

// diffrent command
static unsigned char _socks5_cmd_bind(int fd, char *addrbuf, char *port)
{
    // TODO: pass
    return 0x00;
}

static unsigned char _socks5_cmd_connect(int fd, char *addrbuf, char *port)
{
    
}

static unsigned char _socks5_cmd_udp(int fd, char *addrbuf, char *port)
{
    // TODO: pass
    return 0x00;
}

// handle the socks address type
// set the addr buffer appropriate format
// original buf : 
//          ipv4 -> XXXX (4Bytes)
//          ipv6 -> XXXX XXXX XXXX XXXX
//          domain -> (len byte(1B)) XXXXXX(variable len)
// Trans to this format:
//          ipv4 -> XXXX
//          ipv6 -> XXXX XXXX XXXX XXXX 
//          domain -> XXXXXX + '\0'

// nothing to do in fact
static void _socks5_setaddr_ipv4(char *addrbuf){return;}

// nothing to do in fact
static void _socks5_setaddr_ipv6(char *addrbuf){return;}

static void _socks5_setaddr_domain(char *addrbuf)
{
    unsigned char len = addrbuf[0];
    int tmp = 0;
    for(tmp = 0; tmp < len - 1; ++tmp){
        addrbuf[tmp] = addrbuf[tmp + 1];
    }

    addrbuf[tmp] = '\0';
}

// connect method for diffrent addr type
// return the connection fd
static int _socks5_connect_ipv4(char *addrbuf, char *port)
{
    char address[16];
    unsigned short port_num;
    int fd;
    struct sockaddr_in remote;

    // set ip address
    memset(address, 0, ARRAY_SIZE(address));
    snprintf(addrbuf, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
        addrbuf[0], addrbuf[1], addrbuf[2], addrbuf[3]);
    
    // set port num
    (&port_num)[0] = port[0], (&port_num)[1] = port[1];

    // set remote info to connect
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(address);
    remote.sin_port = htons(port_num);

    // connect 
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
			printf("Error : connect() in ipv4 connect");
			close(fd);
			return -1;
	}
	return fd;
}

static int _socks5_connect_ipv6(char *addrbuf, char *port)
{
    // pass 
    // do not implemented
    return -1;
}

static int _socks5_connect_domain(char *addrbuf, char *port)
{
    char portaddr[6];
    struct addrinfo *res;
    int fd;

    snprintf(portaddr, ARRAY_SIZE(portaddr), "%d", port);
	
    // get address info by domain name
    int ret = getaddrinfo((char *)addrbuf, portaddr, NULL, &res);

    // MACRO in netdb.h -- for getaddrinfo() return
    // should use _GNU_SOURCE_ to get its info in Vscode
    // find a possible connection to this domain
	if (ret == EAI_NODATA) {
			return -1;
	} else if (ret == 0)
    {
		struct addrinfo *r;
		for (r = res; r != NULL; r = r->ai_next) 
        {
			fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
            
            if (fd == -1) 
            {
                continue;
            }
			
            ret = connect(fd, r->ai_addr, r->ai_addrlen);
			
            if (ret == 0) 
            {
				freeaddrinfo(res);
				return fd;
            } else {
                close(fd);
            }
		}
	}
    
}

// handle the socks connect by diffrent addr type
// return the connection fd
static int _socks5_handle_connection(unsigned char addr_type, char *addrbuf, char *port)
{
    switch (addr_type)
    {
    case ATYP_IPV4:
        _socks5_setaddr_ipv4(addrbuf);
        return _socks5_connect_ipv4(addrbuf, port);
        break;
    
    case ATYP_IPV6:
        _socks5_setaddr_ipv6(addrbuf);
        return _socks5_connect_ipv6(addrbuf, port);
        break;

    case ATYP_DOMAIN:
        _socks5_setaddr_domain(addrbuf);
        return _socks5_connect_domain(addrbuf, port);
        break;

    default:
        // error ?
        return -1;
        break;
    }
}


// passing data, as a relay server
static unsigned char _socks5_handle_transfer(int fd, char *databuf);
