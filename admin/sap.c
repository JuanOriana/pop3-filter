#include "./include/sap.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../utils/include/logger.h"

static data_type_correspondence op_to_req_data_type(op_code op_code);
static data_type_correspondence op_to_resp_data_type(op_code op_code);
static int get_packet_size(packet_type packet_type, op_code op_code, char* data);

sap_request * sap_buffer_to_request(char *buffer)
{
    size_t len;

    sap_request * new_request_datagram = calloc(1, sizeof(struct sap_request));
    if (new_request_datagram == NULL)
    {
        return NULL;
    }

    // https://wiki.sei.cmu.edu/confluence/display/c/POS39-C.+Use+the+correct+byte+ordering+when+transferring+data+between+systems ntohl function explanation
    new_request_datagram->v_type = *((uint8_t *) buffer);
    buffer += sizeof(new_request_datagram->v_type);

    new_request_datagram->auth_id = ntohl(*((uint32_t *)buffer));
    buffer += sizeof(new_request_datagram->auth_id);

    new_request_datagram->op_code = *((uint8_t *) buffer);
    buffer += sizeof(new_request_datagram->op_code);

    new_request_datagram->req_id = ntohs(*((uint16_t *)buffer));
    buffer += sizeof(new_request_datagram->req_id);;

    new_request_datagram->auth_id = ntohl(*((uint32_t *)buffer));
    buffer+= sizeof(new_request_datagram->auth_id);

    data_type_correspondence data_type_enum =  op_to_req_data_type(new_request_datagram->op_code);
    switch (data_type_enum) {
        case SAP_SINGLE:
            new_request_datagram->data.sap_single = *((uint8_t *) buffer);
            buffer += sizeof(new_request_datagram->data.sap_single);
            break;
        case SAP_SHORT:
            new_request_datagram->data.sap_short = ntohs(*((uint16_t *)buffer));
            buffer += sizeof(new_request_datagram->data.sap_short);
            break;
        case SAP_LONG:
            new_request_datagram->data.sap_long = ntohl(*((uint32_t *)buffer));
            buffer += sizeof(new_request_datagram->data.sap_long);
            break;
        case SAP_STRING:
            len = strlen(buffer);
            //CHECKEO LEN MAXIMO
            memcpy(new_request_datagram->data.string, buffer, len);
            break;
        case SAP_BLANK:
            new_request_datagram->data.string = NULL;

    }

    return new_request_datagram;
}

sap_response * create_new_sap_response(server_version v_type, status_code status_code, uint16_t req_id,sap_data_type data)
{
    sap_response * new_response_datagram = calloc(1, sizeof(struct sap_response));
    if (new_response_datagram == NULL)
    {
        return NULL;
    }
    else
    {
        new_response_datagram->v_type = v_type;
        new_response_datagram->status_code = status_code;
        new_response_datagram->req_id = req_id;
        new_response_datagram->data = data;
    }
    return new_response_datagram;
}

char * sap_response_to_buffer(sap_response * response, int* size){
    int len, to_copy;
    *size = get_packet_size(SAP_RESP,response->op_code,response->data.string);
    char * buffer = calloc(1, *size);
    char* buffer_travel = buffer;

    to_copy = response->v_type;
    memcpy(buffer_travel,&to_copy,1);
    buffer_travel += 1;

    to_copy = response->status_code;
    memcpy(buffer_travel,&to_copy,1);
    buffer_travel += 1;

    to_copy = htons(response->req_id);
    memcpy(buffer_travel,&to_copy,sizeof(uint16_t));
    buffer_travel += sizeof(uint16_t);

    data_type_correspondence data_type_enum =  op_to_resp_data_type(response->op_code);
    switch (data_type_enum) {
        case SAP_SINGLE:
            to_copy = response->data.sap_single;
            memcpy(buffer_travel, &to_copy, 1);
            break;
        case SAP_SHORT:
            to_copy = htons(response->data.sap_short);
            memcpy(buffer_travel, &to_copy, sizeof(uint16_t));
            break;
        case SAP_LONG:
            to_copy = htons(response->data.sap_long);
            memcpy(buffer_travel, &to_copy, sizeof(uint32_t));
            break;
        case SAP_STRING:
            len = strlen(response->data.string);
            memcpy(buffer_travel, response->data.string, len);
            break;
        case SAP_BLANK:
        default:
            break;
    }

    return buffer;
}



void free_sap_request(sap_request *request)
{
    free(request);
}

void free_sap_response(sap_response *response)
{
    free(response);
}

char* sap_error(status_code status_code){
    switch (status_code) {
        case SC_OK:
            return "OK";
        case SC_COMMAND_UNSUPPORTED:
            return "Command is not supported by server";
        case SC_COMMAND_INVALID_ARGS:
            return "The arguments are not valid for this command";
        case SC_UNAUTHORIZED:
            return "No authorization";
        case SC_VERSION_UNKNOWN:
            return "Unknown SAP version";
        case SC_INTERNAL_SERVER_ERROR:
            return "Internal server error";
    }
}


static data_type_correspondence op_to_req_data_type(op_code op_code){
    switch (op_code) {
        case OP_STATS:
        case OP_SET_TIMEOUT:
            return SAP_SINGLE;
        case OP_SET_BUFF_SIZE:
            return SAP_SHORT;
        case OP_SET_ERROR_FILE:
        case OP_SET_FILTER:
            return SAP_STRING;
        default:
            return SAP_BLANK;
    }
}

static data_type_correspondence op_to_resp_data_type(op_code op_code){
    switch (op_code) {
        case OP_GET_TIMEOUT:
        case OP_IS_FILTER_WORKING:
        case OP_TOGGLE_FILTER:
            return SAP_SINGLE;
        case OP_GET_BUFF_SIZE:
            return SAP_SHORT;
        case OP_STATS:
            return SAP_LONG;
        case OP_GET_ERROR_FILE:
        case OP_GET_FILTER:
            return SAP_STRING;
        default:
            return SAP_BLANK;
    }
}

static int get_packet_size(packet_type packet_type, op_code op_code, char* data){
    int size;
    data_type_correspondence data_type_corr;
    if (packet_type == SAP_REQ){
        size = SAP_REQ_HEADER_SIZE;
        data_type_corr = op_to_req_data_type(op_code);
    }
    else{
        size = SAP_RESP_HEADER_SIZE;
        data_type_corr = op_to_resp_data_type(op_code);
    }

    switch (data_type_corr) {
        case SAP_SINGLE:
            size+=1;
            break;
        case SAP_SHORT:
            size+=2;
            break;
        case SAP_LONG:
            size+=4;
        case SAP_STRING:
            size += data!=NULL?strlen(data):0;
        case SAP_BLANK:
        default:
            size+=0;
    }

    return size;
}