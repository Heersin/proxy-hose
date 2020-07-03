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
    unsigned short remote_port;
    unsigned char *remote_addr;
};

struct SOCKS5_RESPONSE_PACK
{
    unsigned char version;
    unsigned char rep;
    unsigned char rsv;
    unsigned char atype;
    unsigned short bind_port;
    unsigned char *bind_addr;
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



Socks5RequestPacket  init_socks5_request_pack();
void free_socks5_request_pack(Socks5RequestPacket packet);
void free_socks5_response_pack(Socks5ResponsePacket packet);
