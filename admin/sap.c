#include "./include/sap.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../utils/include/logger.h"

static data_type_correspondence op_to_req_data_type(op_code op_code);

sap_request * get_sap_request(uint8_t *buffer)
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


//void prepare_sap_response(buffer *buffer, sap_response *response)
//{
//    if (response == NULL || buffer == NULL)
//    {
//        // ERROR
//    }
//
//    size_t size;
//    void *buffer_write_pointer = buffer_write_ptr(buffer, &size);
//    if (size < RESPONSE_HEADER_SIZE)
//    {
//        // ERROR: no enough space in write buffer
//    }
//
//    memset(buffer_write_pointer, 0, get_sap_response_size(response)); // clean buffer
//
//    int field_bytes;
//    char *buffer_current_pointer = buffer_write_pointer;
//
//    field_bytes = htonl(response->response_code);
//    memcpy(buffer_current_pointer, &field_bytes, sizeof(uint32_t));
//
//    buffer_current_pointer += sizeof(uint32_t); // sizeof response_code field
//
//    field_bytes = htonl(response->data_length);
//    memcpy(buffer_current_pointer, &field_bytes, sizeof(uint32_t));
//
//    buffer_current_pointer += sizeof(uint32_t); // sizeof data_length field
//
//    memcpy(buffer_current_pointer, response->data, response->data_length);
//
//    buffer_write_adv(buffer, get_sap_response_size(response)); // buffer write pointer update
//}

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