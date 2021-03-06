#ifndef SAP_H
#define SAP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#define SAP_REQ_HEADER_SIZE 8
#define SAP_RESP_HEADER_SIZE 5
#define MAX_UDP_SIZE 65507

typedef enum packet_type{
    SAP_REQ,
    SAP_RESP
}packet_type;

#define SAP_OP_SIZE 11

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
    SC_NO_FILTER= 12,
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

#define STAT_TYPE_COUNT 3

typedef enum stat_type
{
    SAP_STAT_HISTORIC,
    SAP_STAT_CURRENT,
    SAP_STAT_BYTES
} stat_type;

typedef union sap_data_type
{
    uint8_t sap_single;
    uint16_t sap_short;
    uint32_t sap_long;
    char string[MAX_UDP_SIZE - SAP_REQ_HEADER_SIZE];

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
    op_code op_code;
    uint16_t req_id;
    sap_data_type data;
} sap_response;

/**
 * Convierte un buffer a un struct de request
 * @param buffer    de donde leer
 * @param request   a donde dejarlo
 * @return          un flag que es 0 en exito y < 0 en error
 */
int sap_buffer_to_request(char *buffer, sap_request* request);

/**
 * Convierte un buffer a un struct de response
 * @param buffer    de donde leer
 * @param response  a donde dejarlo
 * @return          un flag que es 0 en exito y < 0 en error
 */
int sap_buffer_to_response(char *buffer, sap_response * response);

/**
 * Convierte un struct de request a buffer
 * @param request   de donde parsear
 * @param buffer    a donde dejarlo
 * @param size      el tamano del buffer resultante
 * @return          un flag que es 0 en exito y < 0 en error
 */
int sap_request_to_buffer(char* buffer, sap_request * request, int* size);

/**
 * Convierte un struct de response a buffer
 * @param response  de donde parsear
 * @param buffer    a donde dejarlo
 * @param size      el tamano del buffer resultante
 * @return          un flag que es 0 en exito y < 0 en error
 */
int sap_response_to_buffer(char* buffer, sap_response * response, int* size);

/*
 * Devuelven los tipos de dato que corresponden a una operacion determinada
 */
data_type_correspondence op_to_req_data_type(op_code op_code);
data_type_correspondence op_to_resp_data_type(op_code op_code);

/**
 * Devuelve el error de SAP en formato legible
 * @param status_code el codigo de estado
 * @return            el resultado en lenguaje humano
 */
char* sap_error(status_code status_code);

#endif