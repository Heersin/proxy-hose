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

// ================= Response ======================
Socks5ResponsePacket init_socks5_response_pack()
{
    Socks5ResponsePacket packet;
    packet = (Socks5ResponsePacket) malloc(sizeof(struct SOCKS5_RESPONSE_PACK));

    char *bind_addr;
    bind_addr = (char *)malloc(4);   // a 4-bytes addr
    memset(bind_addr, 0x00, 4);

    // just some init value, make no sense
    packet->version = VERSION_5;
    packet->rep = REP_SUCCESS;
    packet->rsv = 0x00;
    packet->atype = ATYP_IPV4;
    packet->bind_port = 0x00;
    packet->bind_addr = bind_addr;

    return packet;
}

Socks5ResponsePacket make_socks5_response_pack(unsigned char rep_code, unsigned char atype, char *addr, unsigned short port)
{
    Socks5ResponsePacket response;

    if(addr == NULL){
        addr = (char *)malloc(4);
        memset(addr, 0x00, 4);
    }

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
        // response->bind_addr = addr;
        set_addr_socks5res(response, addr);
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
        set_addr_socks5res(response, addr);
        response->bind_port = 0x00;
        break;
    }
    
    return response;
}

void free_socks5_response_pack(Socks5ResponsePacket packet)
{
    if(packet->bind_addr != NULL){
        free(packet->bind_addr);
    }

    free(packet);
}
unsigned char send_socks5_response_to_fd(Socks5ResponsePacket packet, int fd)
{
    unsigned char atype;
    char *addr;
    int len;

    if(packet == NULL){
        return HANDLE_FAIL;
    }

    atype = packet->atype;
    if(atype == ATYP_IPV4){
        len = 4;
    }else if(atype == ATYP_IPV6){
        len = 16;
    }else if(atype == ATYP_DOMAIN){
        len = 0;
        addr = packet->bind_addr;
        for(;(addr[len] != '\0');++len){;}  // count the length of domain addr
    }

    writen(fd, &(packet->version), 1);
    writen(fd, &(packet->rep), 1);
    writen(fd, &(packet->rsv), 1);
    writen(fd, &(packet->atype), 1);
    writen(fd, packet->bind_addr, len);
    writen(fd, &(packet->bind_port), 2);

    return HANDLE_SUCCESS;
}
// define getter and setter
void set_version_socks5res(Socks5ResponsePacket packet, unsigned char version){
    packet->version = version;
}
void set_rep_socks5res(Socks5ResponsePacket packet, unsigned char rep){
    packet->rep = rep;
}
void set_atype_socks5res(Socks5ResponsePacket packet, unsigned char atype){
    packet->atype = atype;
}
void set_port_socks5res(Socks5ResponsePacket packet, unsigned short port){
    packet->bind_port = port;
}
void set_addr_socks5res(Socks5ResponsePacket packet, char *addr){
    if(packet->bind_addr != NULL){
        free(packet->bind_addr);
    }
    packet->bind_addr = addr;
}
// ================= Request =====================
Socks5RequestPacket  make_socks5_request_from_fd(int fd)
{
    Socks5RequestPacket request;
    request = init_socks5_request_pack();

    unsigned char rsv;
    unsigned char len;
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
    addr = (char *)malloc(len + 1);
    addr[len] = '\0';
    readn(fd, addr, len);
    free(request->remote_addr);         // free the empty addr
    request->remote_addr = addr;        
    
    // get our port num
    readn(fd, &(request->remote_port), 2);

    // return the packet
    return request; 
}

Socks5RequestPacket  init_socks5_request_pack(){
    Socks5RequestPacket packet;
    packet = (Socks5RequestPacket) malloc(sizeof(struct SOCKS5_REQUEST_PACK));

    char *remote_addr;
    remote_addr = (char *)malloc(4);   // a 4-bytes addr
    memset(remote_addr, 0x00, 4);

    // just some init value, make no sense
    packet->version = VERSION_5;
    packet->cmd = CMD_CONNECT;
    packet->rsv = 0x00;
    packet->atype = ATYP_IPV4;
    packet->remote_port = 0x00;
    packet->remote_addr = remote_addr;

    return packet;
}

// define getter and setter
unsigned char get_version_socks5req(Socks5RequestPacket packet){
    return packet->version;
}
unsigned char get_cmd_socks5req(Socks5RequestPacket packet){
    return packet->cmd;
}
unsigned char get_atype_socks5req(Socks5RequestPacket packet){
    return packet->atype;
}
unsigned short get_port_socks5req(Socks5RequestPacket packet){
    return packet->remote_port;
}
char *get_addr_socks5req(Socks5RequestPacket packet){
    return packet->remote_addr;
}
void free_socks5_request_pack(Socks5RequestPacket packet){
    if(packet->remote_addr != NULL)
        free(packet->remote_addr);
    free(packet);
}
// ================= UDP ==================
Socks5UdpHdr init_socks5_udp_pack(void){
    Socks5UdpHdr socks5_udp;
    char *addr;
    char *databuf;
    socks5_udp = (Socks5UdpHdr)malloc(sizeof(struct SOCKS5_UDP_HEADER));

    // prepare an empty address
    addr = (char *)malloc(4);   // a 4-bytes addr
    memset(addr, 0x00, 4);

    // prepare an empty buffer
    databuf = (char *)malloc(4);
    memset(databuf, 0x00, 4);

    // set 
    socks5_udp->rsv = 0x00;
    socks5_udp->atype = ATYP_IPV4;
    socks5_udp->frag = 0x00;
    socks5_udp->port = 0x00;
    socks5_udp->addr = addr;
    socks5_udp->databuf = databuf; // just the same, 4bytes 0x00

    return socks5_udp;
}
Socks5UdpHdr mkae_socks5_udp_from_fd(int fd)
{
    Socks5UdpHdr request;
    request = init_socks5_request_pack();
    
    unsigned short rsv;
    unsigned char len;
    unsigned char atype;
    char *addr;

    readn(fd, &rsv, 2);
    readn(fd, &(request->frag), 1);
    readn(fd, &(request->atype), 1);

    atype = request->atype;

    switch (atype)
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
    
    addr = (char *)malloc(len + 1);
    readn(fd, &addr, len);
    addr[len] = '\0';

    // set the struct
    free(request->addr);
    request->addr = addr;

    // set dst port
    readn(fd, &(request->port), 2);
    
    // I don't know if there is a proper way to know how much the buffer is;
    // so simply set it as init
    // do nothing

    return request;
}
Socks5UdpHdr make_socks5_udp_pack(unsigned char atype, char *addr, unsigned short port, char *databuf)
{
    Socks5UdpHdr socks_udp;
    socks_udp = init_socks5_udp_pack();

    socks_udp->atype = atype;
    socks_udp->port = port;

    if(addr == NULL){
        addr = (char *)malloc(4);
        memset(addr, 0x00, 4);
    }

    if(databuf == NULL){
        databuf = (char *)malloc(4);
        memset(databuf, 0x00, 4);
    }
    
    set_addr_socks5udp(socks_udp, addr);
    set_data_socks5udp(socks_udp, databuf);

    return socks_udp;
}
void free_socks5_udp_pack(Socks5UdpHdr packet){
    if(packet->addr != NULL){
        free(packet->addr);
    }
    if(packet->databuf != NULL){
        free(packet->addr);
    }

    free(packet);
}

// getter and setter
void set_atype_socks5udp(Socks5UdpHdr packet, unsigned short atype){
    packet->atype = atype;
}
void set_addr_socks5udp(Socks5UdpHdr packet, char *addr){
    if(packet->addr != NULL)
        free(packet->addr);    
    packet->addr = addr;
}
void set_port_socks5udp(Socks5UdpHdr packet, unsigned short port){
    packet->port = port;
}
void set_data_socks5udp(Socks5UdpHdr packet, char *databuf){
    if(packet->databuf != NULL)
        free(packet->databuf);
    packet->databuf = databuf;
}

unsigned char get_atype_socks5udp(Socks5UdpHdr packet){
    return packet->atype;
}
char *get_addr_socks5udp(Socks5UdpHdr packet){
    return packet->addr;
}
unsigned short get_port_socks5udp(Socks5UdpHdr packet){
    return packet->port;
}
char *get_databuf_socks5udp(Socks5UdpHdr packet){
    return packet->databuf;
}
unsigned char get_frag_socks5udp(Socks5UdpHdr packet){
    return packet->frag;
}
