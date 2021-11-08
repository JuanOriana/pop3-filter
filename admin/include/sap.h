#ifndef SAP_H
#define SAP_H

#include "buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define RESPONSE_HEADER_SIZE (4 * sizeof(uint32_t))

typedef enum operation_code
{
    LOGIN = 1,
    //........
} operation_code;

typedef enum server_version
{
    V_1_0_0 = 1,
} server_version;

typedef struct request_sap
{
    char credential[8];
    server_version s_version;
    operation_code op_code;
    size_t data_length;
    void *data;
} request_sap;

typedef enum response_code
{
    RESP_POSITIVE_OK = 200,
    RESP_NEGATIVE_BAD_REQUEST = 400,
    RESP_NEGATIVE_INTERNAL_SERVER_ERROR = 500,
    //........
} response_code;

typedef struct response_sap
{
    response_code response_code;
    size_t data_length;
    void *data;
} response_sap;

request_sap get_sap_request(buffer *buffer);
response_sap create_new_sap_response(response_code response_code, size_t data_length, void *data);

size_t get_sap_response_size(response_sap *response);

void free_sap_request(request_sap *request);
void free_sap_response(response_sap *response);

#endif