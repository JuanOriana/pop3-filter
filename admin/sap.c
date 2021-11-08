#include "./include/sap.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../utils/include/logger.h"

request_sap get_sap_request(buffer *buffer)
{
    request_sap new_request_datagram = calloc(1, sizeof(struct request_sap));
    if (new_request_datagram == NULL)
    {
        // ERROR
    }

    size_t size;
    void *buffer_read_pointer = buffer_read_ptr(buffer, &size);

    // https://wiki.sei.cmu.edu/confluence/display/c/POS39-C.+Use+the+correct+byte+ordering+when+transferring+data+between+systems ntohl function explanation
    new_request_datagram->credential = ntohl(*((uint32_t *)buffer_read_pointer));
    buffer_read_adv(buffer, sizeof(new_request_datagram->credential)); // advance buffer pointer to next field

    buffer_read_pointer = buffer_read_ptr(buffer, &size);
    new_request_datagram->s_version = ntohl(*((uint32_t *)buffer_read_pointer));
    buffer_read_adv(buffer, sizeof(new_request_datagram->version));

    buffer_read_pointer = buffer_read_ptr(buffer, &size);
    new_request_datagram->op_code = ntohl(*((uint32_t *)buffer_read_pointer));
    buffer_read_adv(buffer, sizeof(new_request_datagram->op_code));

    buffer_read_pointer = buffer_read_ptr(buffer, &size);
    new_request_datagram->data_length = ntohl(*((uint32_t *)buffer_read_pointer));
    buffer_read_adv(buffer, sizeof(new_request_datagram->data_length));

    buffer_read_pointer = buffer_read_ptr(buffer, &size);
    new_request_datagram->data = calloc(size, sizeof(char));
    if (new_request_datagram->data == NULL)
    {
        // ERROR
    }
    else
    {
        memcpy(new_request_datagram->data, buffer_read_pointer, size);
    }

    return new_request_datagram;
}

response_sap create_new_sap_response(response_code response_code, size_t data_length, void *data)
{
    response_sap new_response_datagram = calloc(1, sizeof(struct response_sap));
    if (new_response_datagram == NULL)
    {
        // ERROR
    }
    else
    {
        new_response_datagram->response_code = response_code;
        new_response_datagram->data_length = data_length;
        new_response_datagram->data = data;
    }
    return new_response_datagram;
}

size_t get_sap_response_size(response_sap *response)
{
    if (response == NULL)
    {
        // ERROR
    }
    return (int)(response->data_length) + RESPONSE_HEADER_SIZE;
}

void prepare_sap_response(buffer *buffer, response_sap *response)
{
    if (response == NULL || buffer == NULL)
    {
        // ERROR
    }

    size_t size;
    void *buffer_write_pointer = buffer_write_ptr(buffer, &size);
    if (size < RESPONSE_HEADER_SIZE)
    {
        // ERROR: no enough space in write buffer
    }

    memset(buffer_write_pointer, 0, get_sap_response_size(response)); // clean buffer

    int field_bytes;
    char *buffer_current_pointer = buffer_write_pointer;

    field_bytes = htonl(response->response_code);
    memcpy(buffer_current_pointer, &field_bytes, sizeof(uint32_t));

    buffer_current_pointer += sizeof(uint32_t); // sizeof response_code field

    field_bytes = htonl(response->data_length);
    memcpy(buffer_current_pointer, &field_bytes, sizeof(uint32_t));

    buffer_current_pointer += sizeof(uint32_t); // sizeof data_length field

    memcpy(buffer_current_pointer, response->data, response->data_length);

    buffer_write_adv(buffer, get_sap_response_size(response)); // buffer write pointer update
}

void free_sap_request(request_sap *request)
{
    if (request == NULL)
    {
        // ERROR
    }
    free(request);
}

void free_sap_response(response_sap *response)
{
    if (response == NULL)
    {
        // ERROR
    }
    free(response);
}