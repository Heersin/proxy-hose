#include "connect.h"

// some utils
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
static int _socks5_connect_ipv6(char *addrbuf, unsigned short port)
{
    // pass 
    // do not implemented
    return -1;
}

static int _socks5_connect_ipv4(char *addrbuf, unsigned short port)
{
    char address[16];
    int fd;
    struct sockaddr_in remote;

    // set ip address
    memset(address, 0, ARRAY_SIZE(address));
    snprintf(addrbuf, ARRAY_SIZE(address), "%hhu.%hhu.%hhu.%hhu",
        addrbuf[0], addrbuf[1], addrbuf[2], addrbuf[3]);
    
    // set remote info to connect
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(address);
    remote.sin_port = htons(port);

    // connect 
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
			printf("Error : connect() in ipv4 connect");
			close(fd);
			return CONNECT_REJECT_ERROR;
	}
	return fd;
}

static int _socks5_connect_domain(char *addrbuf, unsigned short port)
{
    char portbuf[6];
    struct addrinfo *res;
    int fd;

    snprintf(portbuf, ARRAY_SIZE(portbuf), "%d", port);
	
    // get address info by domain name
    int ret = getaddrinfo((char *)addrbuf, portbuf, NULL, &res);

    // MACRO in netdb.h -- for getaddrinfo() return
    // should use _GNU_SOURCE_ to get its info in Vscode
    // find a possible connection to this domain
	if (ret == EAI_NODATA) {
			return CONNECT_HOST_ERROR;
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

        return CONNECT_REJECT_ERROR;
	}
    
}

// handle the socks connect by diffrent addr type
// return the connection fd
int socks5_handle_connection(unsigned char addr_type, char *addrbuf, unsigned short port)
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
        return CONNECT_FORMAT_ERROR;
        break;
    }
}


// should set up info in the empty sockaddr_in struct!
static int _socks5_sockudp_ipv6(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr)
{return CONNECT_REJECT_ERROR;}
static int _socks5_sockudp_ipv4(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr)
{return CONNECT_REJECT_ERROR;}
static int _socks5_sockudp_domain(char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr)
{return CONNECT_REJECT_ERROR;}

int socks5_handle_udpsock(unsigned char addrtype, char *addrbuf, unsigned short port, struct sockaddr_in *empty_addr)
{
    // should set up info in the empty sockaddr_in struct!
    switch (addrtype)
    {
    case ATYP_IPV4:
        _socks5_setaddr_ipv4(addrbuf);
        return _socks5_sockudp_ipv4(addrbuf, port, empty_addr);
        break;
    
    case ATYP_IPV6:
        _socks5_setaddr_ipv6(addrbuf);
        return _socks5_sockudp_ipv6(addrbuf, port, empty_addr);
        break;

    case ATYP_DOMAIN:
        _socks5_setaddr_domain(addrbuf);
        return _socks5_sockudp_domain(addrbuf, port, empty_addr);
        break;

    default:
        // error ?
        return CONNECT_FORMAT_ERROR;
        break;
    }
}