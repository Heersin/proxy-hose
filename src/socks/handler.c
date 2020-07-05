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
        response = make_socks5_response_pack(REP_DISALLOW, 0x00, NULL, 0x00);
        send_socks5_response_to_fd(response, (int)fd);
        free_socks5_response_pack(response);
        return HANDLE_FORMAT_FAIL;
    }

    // handle different command here
    // client ----request----> server ( Handle Request ) 
    // client <---response---- server ( Make Response )
    handle_result = _socks5_handle_cmd((int)fd, request);

    // agter all that done, we destroy the request
    free_socks5_request_pack(request);

    return handle_result;
}


// handle the socks cmd, call the specified function
// to handle diffrent cmd
// return : HANDLE RESULT
static unsigned char _socks5_handle_cmd(int fd, Socks5RequestPacket request)
{
    unsigned char rep_code;
    unsigned char cmd;

    // get required args
    cmd = get_cmd_socks5req(request);

    // prepare an empty response packet
    Socks5ResponsePacket empty_response;
    empty_response = init_socks5_response_pack();
    
    // handle different commands
    // set the info in the empty response
    switch (cmd)
    {
    case CMD_CONNECT:
        rep_code = _socks5_cmd_connect(request, empty_response, fd);
        break;
    
    case CMD_BIND:
        rep_code = _socks5_cmd_bind(request, empty_response, fd);
        break;
    
    case CMD_UDP:
        rep_code = _socks5_cmd_udp(request, empty_response, fd);
        break;

    default:
        // error ?
        rep_code = REP_UNSUPPORTCMD;
        break;
    }

    // use remote addr as relay server
    if((!is_as_relay_server()) || (rep_code == REP_UNSUPPORTCMD)){
        set_rep_socks5res(empty_response, rep_code);
        send_socks5_response_to_fd(empty_response, fd);
    } // else do nothing, send action is done by the relay server procedure in _socks_cmd_xxx()

    // no matter how, free the request and response, and close fd
    free_socks5_request_pack(request);
    free_socks5_response_pack(empty_response);
    close(fd);

    // if rep is fail, then inform our socks server that the handle procedure is failed
    if(rep_code != REP_SUCCESS)
        return HANDLE_FAIL;
    else
        return HANDLE_SUCCESS;
}

// diffrent command
static unsigned char _socks5_cmd_bind(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd)
{
    // TODO: pass
    // if I want to implement the bind
    // then I should implement a table to store the connect to our socks server
    // because in RFC, "BIND" required an existing connection create by cmd "CONNECT"
    return REP_UNSUPPORTCMD;
}

static unsigned char _socks5_cmd_connect(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd)
{
    // TODO : passportaddr
    // test if the server is ok
    if(is_as_relay_server()){
        // set response and waiting connection
        // may create a process to handle relay
        return socks5_start_relay_server(request, empty_response, fd);
    }

    // use remote relay server
    malloc_string addrport;
    char *relay_addr;
    unsigned short port;
    unsigned char atype;
    int relay_fd;

    addrport = _load_relay_server_config(NULL);
    atype = addrport[0];
    port = split_addr_port(addrport + 1, relay_addr);
    relay_fd = socks5_handle_connection(atype, relay_addr, port);

    // set, but do nothing, the upper layer will send it
    // realy server is dead
    if(relay_fd == -1){
        set_rep_socks5res(empty_response, REP_REJECT);
        return REP_REJECT;
    }

    // close test connection
    close(relay_fd);
    free(addrport);

    set_atype_socks5res(empty_response, atype);
    set_rep_socks5res(empty_response, REP_SUCCESS);
    set_addr_socks5res(empty_response, relay_addr);
    set_port_socks5res(empty_response, port);
    return REP_SUCCESS;
}

static unsigned char _socks5_cmd_udp(Socks5RequestPacket request, Socks5ResponsePacket empty_response, int fd)
{
    if(is_as_relay_server()){
        return socks5_start_udp_server(request, empty_response, fd);
    }
       
    // use remote relay server
    malloc_string addrport;
    char *relay_addr;
    unsigned short port;
    unsigned char atype;
    int relay_fd;

    addrport = _load_udp_server_config(NULL);
    atype = addrport[0];
    port = split_addr_port(addrport + 1, relay_addr);
    relay_fd = socks5_handle_connection(atype, relay_addr, port);

    // set, but do nothing, the upper layer will send it
    // if the realy server is dead, treat as rep_reject
    if(relay_fd == -1){
        set_rep_socks5res(empty_response, REP_REJECT);
        return REP_REJECT;
    }

    // close test connection
    close(relay_fd);
    free(addrport);

    set_atype_socks5res(empty_response, atype);
    set_rep_socks5res(empty_response, REP_SUCCESS);
    set_addr_socks5res(empty_response, relay_addr);
    set_port_socks5res(empty_response, port);
    return REP_SUCCESS;
}
