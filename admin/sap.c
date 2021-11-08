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

    new_request_datagram->credential = ntohl(*((uint32_t *)buffer_read_pointer));
    buffer_read_adv(buffer, sizeof(new_request_datagram->credential)); // avanzo el punter de lectura al siguiente elemnto de la estructura

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

void free_sap_request(request_sap request)
{
    if (request == NULL)
    {
        // ERROR
    }
    free(request);
}

void free_sap_response(response_sap response)
{
    if (response == NULL)
    {
        // ERROR
    }
    free(response);
}