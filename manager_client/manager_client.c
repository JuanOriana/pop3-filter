#include "include/manager_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../manager/include/sap.h"
#include "../utils/include/logger.h"
#include "../include/args.h"

#define MAXLINE 1024
#define MAX_REQ_ID 65535
#define SERVER_VERSION SAP_V_1_0_0
#define AUTH 0

// For Mac OS
#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

sap_response response;
sap_request  request;
uint16_t req_id;

#define COMMAND_TOTAL_COUNT 11

typedef enum client_commands{
    C_CM_HISTORIC,
    C_CM_CURRENT,
    C_CM_TRANSFER,
    C_CM_GET_BUFF,
    C_CM_SET_BUFF,
    C_CM_GET_TIMEOUT,
    C_CM_SET_TIMEOUT,
    C_CM_SET_ERROR,
    C_CM_GET_ERROR,
    C_CM_GET_FILTER,
    C_CM_SET_FILTER,
} client_commands;

void build_blank_request(sap_request * new_request, op_code op_code);
void build_single_request(sap_request * new_request,op_code op_code,uint8_t single_data);
void build_short_request(sap_request * new_request,op_code op_code,uint16_t short_data);
void build_long_request(sap_request * new_request,op_code op_code,uint16_t long_data);
void historic_connections_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void current_connections_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void transfered_bytes_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void get_buff_size_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void set_buff_size_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void get_timeout_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void set_timeout_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void get_error_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void set_error_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void get_filter_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);
void set_filter_req(sap_request *,uint8_t, u_int16_t, uint32_t, char *);


typedef void (*handler_fun_type) (sap_request *,uint8_t,u_int16_t, uint32_t, char *);

handler_fun_type handlers[] = {historic_connections_req, current_connections_req, transfered_bytes_req,
                               get_buff_size_req, set_buff_size_req, get_timeout_req, set_timeout_req,
                               get_error_req,set_error_req, get_filter_req, set_filter_req};
int go_on = 1;

int main() {
    int sockfd;
    struct sockaddr_in servaddr;
    char buffer_in[1024], buffer_out[1024], input[1024];
    memset(buffer_in, 0, 1024);
    memset(buffer_out, 0, 1024);

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(9090);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    while(go_on) {
        memset(input, 0, 1024);
        scanf("%s",input);
        printf("%s",input);
        request.op_code = OP_GET_FILTER;
        request.req_id = 1;
        request.auth_id = 42;
        request.v_type = SAP_V_1_0_0;

        int n;
        socklen_t len;

        if (sap_request_to_buffer(buffer_out, &request, &n) < 0) {
            log(ERROR, "Error converting request to buffer");
        }

        sendto(sockfd, buffer_out, n,
               MSG_CONFIRM, (const struct sockaddr *) &servaddr,
               sizeof(servaddr));

        log(DEBUG, "Sending message!.\n");

        n = recvfrom(sockfd, (char *) buffer_in, MAXLINE,
                     MSG_WAITALL, (struct sockaddr *) &servaddr,
                     &len);

        if (sap_buffer_to_response(buffer_in, &response) < 0) {
            log(ERROR, "Error converting buffer to response");

        }
        log(DEBUG, "V-type: %d\nreq_id: %d\nop_code: %d\nstatus_code %d\n",
            response.v_type, response.req_id, response.op_code, response.status_code);
    }

    close(sockfd);
    return 0;
}


void build_blank_request(sap_request * new_request, op_code op_code){
    new_request->v_type = SERVER_VERSION;
    new_request->req_id = req_id++;
    new_request->op_code = op_code;
    new_request->auth_id = AUTH;
}

void build_single_request(sap_request * new_request,op_code op_code,uint8_t single_data){
    build_blank_request(new_request,op_code);
    new_request->data.sap_single = single_data;
}

void build_short_request(sap_request * new_request,op_code op_code,uint16_t short_data){
    build_blank_request(new_request,op_code);
    new_request->data.sap_short = short_data;
}

void build_long_request(sap_request * new_request,op_code op_code,uint16_t long_data){
    build_blank_request(new_request,op_code);
    new_request->data.sap_long= long_data;
}

void build_string_request(sap_request * new_request,op_code op_code, char* string, int len ){
    build_blank_request(new_request,op_code);
    memcpy(new_request->data.string,string,len);
}

void historic_connections_req(sap_request * new_request,uint8_t single_data,
                              u_int16_t short_data, uint32_t long_data, char * string_data){
    build_single_request(new_request,0,0);
}

void current_connections_req(sap_request * new_request,uint8_t single_data,
                             u_int16_t short_data, uint32_t long_data, char * string_data){
    build_single_request(new_request,0,1);
}

void transfered_bytes_req(sap_request * new_request,uint8_t single_data,
                          u_int16_t short_data, uint32_t long_data, char * string_data){
    build_single_request(new_request,0,2);
}

void get_buff_size_req(sap_request * new_request,uint8_t single_data,
                       u_int16_t short_data, uint32_t long_data, char * string_data){
    build_blank_request(new_request,1);
}

void set_buff_size_req(sap_request * new_request,uint8_t single_data,
                       u_int16_t short_data, uint32_t long_data, char * string_data){
    build_short_request(new_request,2,short_data);
}

void get_timeout_req(sap_request * new_request,uint8_t single_data,
                     u_int16_t short_data, uint32_t long_data, char * string_data){
    build_blank_request(new_request,3);
}

void set_timeout_req(sap_request * new_request,uint8_t single_data,
                     u_int16_t short_data, uint32_t long_data, char * string_data){
    build_single_request(new_request,4,single_data);
}

void get_error_req(sap_request * new_request,uint8_t single_data, u_int16_t short_data,
                   uint32_t long_data, char * string_data){
    build_blank_request(new_request,5);
}

void set_error_req(sap_request * new_request,uint8_t single_data, u_int16_t short_data,
                   uint32_t long_data, char * string_data){
    build_string_request(new_request,6,string_data,strlen(string_data));
}

void get_filter_req(sap_request * new_request,uint8_t single_data, u_int16_t short_data,
                    uint32_t long_data, char * string_data){
    build_blank_request(new_request,7);
}

void set_filter_req(sap_request * new_request,uint8_t single_data, u_int16_t short_data,
                    uint32_t long_data, char * string_data){
    build_string_request(new_request,8,string_data, strlen(string_data));
}

void handle_response(sap_response new_response, char * prev_message){
    if (new_response.status_code != 0){
        printf("Error! %s", sap_error(new_response.status_code));
    }
    data_type_correspondence data_type = op_to_resp_data_type(new_response.op_code);

    switch (data_type) {
        case SAP_SINGLE:
            printf("%s %d",prev_message,new_response.data.sap_single);
            break;
        case SAP_SHORT:
            printf("%s %d",prev_message,new_response.data.sap_short);
            break;
        case SAP_LONG:
            printf("%s %d",prev_message,new_response.data.sap_long);
            break;
        case SAP_STRING:
            printf("%s %s",prev_message,new_response.data.string);
            break;
        case SAP_BLANK:
            printf("%s",prev_message);
            break;
    }

}