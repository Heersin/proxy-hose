#include "socks_relay.h"

// transport from connect_fd to remote_fd
unsigned char socks5_start_relay_server(Socks5RequestPacket request, Socks5ResponsePacket response, int connect_fd)
{
    int remote_fd;
    char tmp_buf[512];
    int recv_data_cnt;

    unsigned short remote_port;
    char *remote_addr;
    unsigned char atype;
    unsigned char rep_code;

    // extract data from request
    atype = get_atype_socks5req(request);
    remote_addr = get_addr_socks5req(request);
    remote_port = get_port_socks5req(request);

    // connect to remote and handle error tips
    remote_fd = socks5_handle_connection(atype, remote_addr, remote_port);
    if (remote_fd == CONNECT_FORMAT_ERROR){rep_code = REP_NETWORK_UNREACHABLE;}
    else if (remote_fd == CONNECT_HOST_ERROR){rep_code = REP_HOST_UNREACHABLE;}
    else if (remote_fd == CONNECT_REJECT_ERROR){rep_code = REP_REJECT;}
    else{rep_code = REP_FAIL;}

    // prepare the socks response packet
    // -- keep addr and port empty(zeros) when use this inner realy_server
    // -- keep atype as ipv4
    // -- set rep code according to the remote server status(if error, set rep_xxx)
    set_rep_socks5res(response, REP_SUCCESS);
    
    // send socks response to client
    send_socks5_response_to_fd(response, connect_fd);

    // if rep_code is fail, we don't wait client anymore
    if(rep_code == REP_FAIL)
        return REP_FAIL;
   
    // loop to wait data and send them
    // !!! single direction !!!
    // FIX: use other ways to do that 
    while (TRUE)
    {
        recv_data_cnt = recv(connect_fd, tmp_buf, 512, 0);
        send(remote_fd, (void *)tmp_buf, recv_data_cnt, 0);
    }
    
    return REP_SUCCESS;
}

unsigned char socks5_start_udp_server(Socks5RequestPacket request, Socks5ResponsePacket response, int connect_fd)
{
    // use the original TCP connection to communicate with socket client
    Socks5UdpHdr client_udp_request;
    Socks5UdpHdr client_udp_response;

    // init a socket for remote server
    int remote_fd;
    char *databuf;
    int recv_data_cnt;
    int BUFLEN = 1024;

    unsigned short remote_port;
    char *remote_addr;
    unsigned char atype;
    unsigned char rep_code;
    struct sockaddr_in sock_udp_addr;

    // extract data from request
    atype = get_atype_socks5req(request);
    remote_addr = get_addr_socks5req(request);
    remote_port = get_port_socks5req(request);

    // create udp socket to remote and handle error tips
    remote_fd = socks5_handle_udpsock(atype, remote_addr, remote_port, &sock_udp_addr);
    if (remote_fd == CONNECT_FORMAT_ERROR){rep_code = REP_NETWORK_UNREACHABLE;}
    else if (remote_fd == CONNECT_HOST_ERROR){rep_code = REP_HOST_UNREACHABLE;}
    else if (remote_fd == CONNECT_REJECT_ERROR){rep_code = REP_REJECT;}
    else{rep_code = REP_FAIL;}

    // prepare the socks response packet
    // -- keep addr and port empty(zeros) when use this inner realy_server
    // -- keep atype as ipv4
    // -- set rep code according to the remote server status(if error, set rep_xxx)
    set_rep_socks5res(response, REP_SUCCESS);
    
    // send socks response to client
    send_socks5_response_to_fd(response, connect_fd);

    // if rep_code is fail, we don't wait client anymore
    if(rep_code == REP_FAIL)
        return REP_FAIL;


    // handle the sock client to this relay server    
    // encapsulate
    while (TRUE)
    {
        client_udp_request = mkae_socks5_udp_from_fd(connect_fd);
        
        // not support fragments
        if(get_frag_socks5udp(client_udp_request) != 0x00){
            //drop
            free_socks5_udp_pack(client_udp_request);
            continue;
        }

        databuf = get_databuf_socks5udp(client_udp_request);
        sendto(remote_fd, databuf, BUFLEN, 0, (struct sockaddr *)&sock_udp_addr, sizeof(sock_udp_addr));
        free_socks5_udp_pack(client_udp_request);
    }
    return REP_SUCCESS;

    // do not support fragments
}