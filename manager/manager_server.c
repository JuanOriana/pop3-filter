#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "./include/sap.h"
#include "../include/args.h"
#include "../utils/include/logger.h"
#include "../utils/include/selector.h"

#define SERVER_VERSION SAP_V_1_0_0
#define AUTH 0
#define MAX_LINE 1024

/*
 * Creacion de response genericas
 */
void build_blank_response_with_status(sap_response * new_response, sap_request new_request, status_code status);
void build_blank_response(sap_response * new_response, sap_request new_request);
void build_single_response(sap_response * new_response,sap_request new_request,uint8_t single_data);
void build_short_response(sap_response * new_response,sap_request new_request,uint16_t short_data);
void build_long_response(sap_response * new_response,sap_request new_request,uint16_t long_data);
void build_string_response(sap_response * new_response,sap_request new_request,char* string);

typedef void (*resp_handler_fun_type) (sap_response *, sap_request);

/*
 * Creacion de response especificas
 */
void stats_resp(sap_response * new_response, sap_request new_request);
void get_buff_size_resp(sap_response * new_response, sap_request new_request);
void set_buff_size_resp(sap_response * new_response, sap_request new_request);
void get_timeout_resp(sap_response * new_response, sap_request new_request);
void set_timeout_resp(sap_response * new_response, sap_request new_request);
void get_error_resp(sap_response * new_response, sap_request new_request);
void set_error_resp(sap_response * new_response, sap_request new_request);
void get_filter_resp(sap_response * new_response, sap_request new_request);
void set_filter_resp(sap_response * new_response, sap_request new_request);

resp_handler_fun_type resp_handlers[] = {
        stats_resp, get_buff_size_resp, set_buff_size_resp, get_timeout_resp, set_timeout_resp,
        get_error_resp, set_error_resp, get_filter_resp, set_filter_resp
};

extern struct pop3_proxy_state pop3_proxy_state;

sap_response response;
sap_request  request;

void manager_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer_in[MAX_LINE], buffer_out[MAX_LINE];
    int out_len = 0;

    //Limpiamos buffers
    memset(buffer_in, 0, MAX_LINE);
    memset(buffer_out, 0, MAX_LINE);

    ssize_t n = recvfrom(key->fd, buffer_in, MAX_LINE, 0, (struct sockaddr *)&client_addr, &client_addr_len);

    if (n <= 0)
    {
        log(ERROR, "recvfrom() failed: %s ", strerror(errno));
    }

    if (sap_buffer_to_request(buffer_in, &request) < 0){
        log(ERROR,"Error converting buffer to request");
    }

    if (request.auth_id != AUTH){
        build_blank_response_with_status(&response,request,SC_UNAUTHORIZED);
    }
    else if (request.v_type > SERVER_VERSION){
        build_blank_response_with_status(&response,request,SC_VERSION_UNKNOWN);
    }
    else if (request.op_code > SAP_OP_SIZE){
        build_blank_response_with_status(&response,request,SC_COMMAND_UNSUPPORTED);
    }
    else{
        resp_handlers[request.op_code](&response,request);
    }

    if (sap_response_to_buffer(buffer_out,&response,&out_len) < 0) {
        log(ERROR, "Error converting response to buffer");
    }

    sendto(key->fd, buffer_out, out_len, 0, (const struct sockaddr *)&client_addr, client_addr_len);

}


void build_blank_response_with_status(sap_response * new_response, sap_request new_request, status_code status){
    new_response->v_type = SERVER_VERSION;
    new_response->req_id = new_request.req_id;
    new_response->op_code = new_request.op_code;
    new_response->status_code = status;
}

void build_blank_response(sap_response * new_response, sap_request new_request){
    build_blank_response_with_status(new_response,new_request,SC_OK);
}

void build_single_response(sap_response * new_response,sap_request new_request,uint8_t single_data){
    build_blank_response(new_response,new_request);
    new_response->data.sap_single = single_data;
}

void build_short_response(sap_response * new_response,sap_request new_request,uint16_t short_data){
    build_blank_response(new_response,new_request);
    new_response->data.sap_short = short_data;
}

void build_long_response(sap_response * new_response,sap_request new_request,uint16_t long_data){
    build_blank_response(new_response,new_request);
    new_response->data.sap_long= long_data;
}

void build_string_response(sap_response * new_response,sap_request new_request,char* string){
    build_blank_response(new_response,new_request);
    strcpy(new_response->data.string,string);
}

void stats_resp(sap_response * new_response, sap_request new_request){
    if (new_request.data.sap_single > STAT_TYPE_COUNT){
        build_blank_response_with_status(new_response,new_request,SC_COMMAND_INVALID_ARGS);
        return;
    }

    build_blank_response(new_response,new_request);
    switch (new_request.data.sap_single) {
        case SAP_STAT_HISTORIC:
            new_response->data.sap_long = pop3_proxy_state.historic_connections;
            break;
        case SAP_STAT_CURRENT:
            new_response->data.sap_long = pop3_proxy_state.current_connections;
            break;
        case SAP_STAT_BYTES:
            new_response->data.sap_long = pop3_proxy_state.bytes_transfered;
            break;
    }
}

void get_buff_size_resp(sap_response * new_response, sap_request new_request){
    build_short_response(new_response,new_request,pop3_proxy_state.buff_size);
}

void set_buff_size_resp(sap_response * new_response, sap_request new_request){
    build_blank_response(new_response,new_request);
    pop3_proxy_state.buff_size = new_request.data.sap_short;
}

void get_timeout_resp(sap_response * new_response, sap_request new_request){
    build_single_response(new_response,new_request,pop3_proxy_state.timeout);
}

void set_timeout_resp(sap_response * new_response, sap_request new_request){
    build_blank_response(new_response,new_request);
    pop3_proxy_state.timeout = new_request.data.sap_single;
}

void get_error_resp(sap_response * new_response, sap_request new_request){
    build_string_response(new_response,new_request,pop3_proxy_state.error_file);
}

void set_error_resp(sap_response * new_response, sap_request new_request){
    build_blank_response(new_response,new_request);
    strcpy(pop3_proxy_state.error_file,new_request.data.string);
}

void get_filter_resp(sap_response * new_response, sap_request new_request){
    build_string_response(new_response,new_request,pop3_proxy_state.filter);

}

void set_filter_resp(sap_response * new_response, sap_request new_request){
    build_blank_response(new_response,new_request);
    strcpy(pop3_proxy_state.filter,new_request.data.string);
}