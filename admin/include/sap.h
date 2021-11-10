#ifndef SAP_H
#define SAP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define SAP_REQ_HEADER_SIZE 8
#define SAP_RESP_HEADER_SIZE 4

typedef enum packet_type{
    SAP_REQ,
    SAP_RESP
}packet_type;

typedef enum op_code
{
    OP_STATS,
    OP_GET_BUFF_SIZE,
    OP_SET_BUFF_SIZE,
    OP_GET_TIMEOUT,
    OP_SET_TIMEOUT,
    OP_GET_ERROR_FILE,
    OP_SET_ERROR_FILE,
    OP_GET_FILTER,
    OP_SET_FILTER,
    OP_IS_FILTER_WORKING,
    OP_TOGGLE_FILTER
} op_code;

typedef enum server_version
{
    SAP_V_1_0_0 = 1,
} server_version;

typedef enum status_code
{
    SC_OK = 0,
    SC_COMMAND_UNSUPPORTED = 10,
    SC_COMMAND_INVALID_ARGS= 11,
    SC_UNAUTHORIZED = 20,
    SC_VERSION_UNKNOWN = 30,
    SC_INTERNAL_SERVER_ERROR = 40,
} status_code;

typedef enum data_type_correspondence
{
    SAP_BLANK,
    SAP_SINGLE,
    SAP_SHORT,
    SAP_LONG,
    SAP_STRING,
} data_type_correspondence;

typedef union sap_data_type
{
    uint8_t sap_single;
    uint16_t sap_short;
    uint32_t sap_long;
    char * string;

}sap_data_type;

typedef struct sap_request
{
    server_version v_type;
    uint32_t auth_id;
    op_code op_code;
    uint16_t req_id;
    sap_data_type data;
} sap_request;

typedef struct sap_response
{
    server_version v_type;
    status_code status_code;
    // Op code its responding to. This is NOT sent in the protocol but it helps for size and type calcs.
    op_code op_code;
    uint16_t req_id;
    sap_data_type data;
} sap_response;

sap_request * sap_buffer_to_request(uint8_t *buffer);
uint8_t * sap_response_to_buffer(sap_response * response);
sap_response * create_new_sap_response(server_version v_type, status_code status_code, uint16_t req_id,sap_data_type data);
//void prepare_sap_response(buffer *buffer, sap_response *response);

void free_sap_request(sap_request *request);
void free_sap_response(sap_response *response);

char* sap_error(status_code status_code);

#endif