#include "socks_pack.h"

// should have use __attribute__((packed)) here
// if I want to success network packet easily
// but I would pass the data to process them, 
// so the non-aligned access may cause errors in different os
// chose normal way to implement it
struct SOCKS5_REQUEST_PACK
{
    unsigned char version;
    unsigned char cmd;
    unsigned char rsv;
    unsigned char atype;
    unsigned short remote_port; //net ocets(net byte order)
    char *remote_addr;
};

struct SOCKS5_RESPONSE_PACK
{
    unsigned char version;
    unsigned char rep;
    unsigned char rsv;
    unsigned char atype;
    unsigned short bind_port;
    char *bind_addr;
};

struct SOCKS5_UDP_HEADER
{
    unsigned short rsv;
    unsigned short port;
    unsigned char frag;
    unsigned char atype;
    char *addr;
    char *databuf;
};

Socks5ResponsePacket init_socks5_response_pack()
{
    Socks5ResponsePacket packet;
    packet = (Socks5ResponsePacket) malloc(sizeof(struct SOCKS5_REQUEST_PACK));

    // just some init value, make no sense
    packet->version = VERSION_5;
    packet->rep = REP_SUCCESS;
    packet->rsv = 0x00;
    packet->atype = ATYP_IPV4;
    packet->bind_port = 0x00;
    packet->bind_addr = NULL;

    return packet;
}

Socks5ResponsePacket make_socks5_response_pack(unsigned char rep_code, unsigned char atype, char *addr, unsigned short port)
{
    Socks5ResponsePacket response;

    // prepare a new packet
    response = init_socks5_response_pack();
    if (response == NULL)
        return NULL;

    response->rep = rep_code;

    switch (rep_code)
    {
        // success state
        // there should have been a malloc to create array 
        // store these data and send together
        // but I keep it simple now
    case REP_SUCCESS:
        response->atype = atype;  // ipv4 is recommended
        response->bind_addr = addr;
        response->bind_port = port;
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
        // I though we can just set addr and bind_port as all zeros
        // but keep simple now

        // WARNING:This is riskful to set them all zeros
        // Because the client program may check the response
        // The Addr Type in our response may conflict with client request
        // so it's possible that client would throw it or just crash~
        response->atype = atype;
        response->bind_addr = addr;
        response->bind_port = 0x00; 
        break;
    }
    
    return response;
}


Socks5RequestPacket  make_socks5_request_from_fd(int fd)
{
    Socks5RequestPacket request;
    
    unsigned rsv;
    unsigned len;
    char *addr;

    readn(fd, &(request->version), 1);
    readn(fd, &(request->cmd), 1);
    readn(fd, &rsv, 1);
    readn(fd, &(request->atype), 1);

    // re use this variable to store type code
    rsv = request->atype;

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
        readn(fd, &len, 1);
        break;
    default:
        // return HANDLE_FORMAT_FAIL;
        return NULL;
        break;
    }

    // create a space to store addr info
    // even thought it do nothing for last byte
    // just keep it, for memory debug to locate error
    addr = (char *)malloc(sizeof(len + 1));
    addr[len] = '\0';
    readn(fd, addr, len);
    request->remote_addr = addr;
    
    // get our port num
    readn(fd, &(request->remote_port), 2);

    // return the packet
    return request; 
}

Socks5RequestPacket  init_socks5_request_pack();
void free_socks5_request_pack(Socks5RequestPacket packet);
void free_socks5_response_pack(Socks5ResponsePacket packet);
