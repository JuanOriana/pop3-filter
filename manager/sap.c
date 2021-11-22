
#include "./include/sap.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/**
 * Devuelve le tamano de un paquete dado su tipo de operacion y si es respuesta o request
 */
static int get_packet_size(packet_type packet_type, op_code op_code, char* data);
/**
 * Lee de un buffer el tipo de dato que corresponda
 */
static void assign_proper_data_type(sap_data_type * data, data_type_correspondence data_type_enum, char* buffer);
/**
 * Carga un buffer con el tipo de dato que le corresponda
 */
static void copy_data_to_buff(sap_data_type data, data_type_correspondence data_type_enum, char* buffer);

int sap_buffer_to_request(char *buffer, sap_request * request)
{

    if (buffer == NULL || request == NULL){
        return -1;
    }

    request->v_type = *((uint8_t *) buffer);
    buffer += sizeof(uint8_t);

    request->auth_id = ntohl(*((uint32_t *)buffer));
    buffer += sizeof(uint32_t);

    request->op_code = *((uint8_t *) buffer);
    buffer += sizeof(uint8_t);

    request->req_id = ntohs(*((uint16_t *)buffer));
    buffer += sizeof(uint16_t);

    assign_proper_data_type(&request->data,op_to_req_data_type(request->op_code), buffer);

    return 0;

}

int sap_buffer_to_response(char *buffer, sap_response * response)
{
    if (buffer == NULL || response == NULL){
        return -1;
    }

    response->v_type = *((uint8_t *) buffer);
    buffer += sizeof(uint8_t);

    response->status_code = *((uint8_t *) buffer);
    buffer += sizeof(uint8_t);

    response->op_code = *((uint8_t *) buffer);
    buffer += sizeof(uint8_t);

    response->req_id = ntohs(*((uint16_t *)buffer));
    buffer += sizeof(uint16_t);

    if (response->status_code == SC_OK)
        assign_proper_data_type(&response->data,op_to_resp_data_type(response->op_code), buffer);

    return 0;

}

int sap_request_to_buffer(char* buffer, sap_request * request, int* size){

    if (buffer == NULL || request == NULL){
        return -1;
    }

    int to_copy;
    *size = get_packet_size(SAP_REQ,request->op_code,request->data.string);
    char* buffer_travel = buffer;

    to_copy = request->v_type;
    memcpy(buffer_travel,&to_copy,sizeof(uint8_t));
    buffer_travel += sizeof(uint8_t);

    to_copy = htonl(request->auth_id);
    memcpy(buffer_travel,&to_copy,sizeof(uint32_t));
    buffer_travel += sizeof(uint32_t);

    to_copy = request->op_code;
    memcpy(buffer_travel,&to_copy,sizeof(uint8_t));
    buffer_travel += sizeof(uint8_t);

    to_copy = htons(request->req_id);
    memcpy(buffer_travel,&to_copy,sizeof(uint16_t));
    buffer_travel += sizeof(uint16_t);

    copy_data_to_buff(request->data, op_to_req_data_type(request->op_code), buffer_travel);

    return 0;

}

int sap_response_to_buffer(char* buffer,sap_response * response, int* size){

    if (buffer == NULL || response == NULL){
        return -1;
    }

    int to_copy;
    *size = get_packet_size(SAP_RESP,response->op_code,response->data.string);
    char* buffer_travel = buffer;

    to_copy = response->v_type;
    memcpy(buffer_travel,&to_copy,sizeof(uint8_t));
    buffer_travel += sizeof(uint8_t);

    to_copy = response->status_code;
    memcpy(buffer_travel,&to_copy,sizeof(uint8_t));
    buffer_travel += sizeof(uint8_t);

    to_copy = response->op_code;
    memcpy(buffer_travel,&to_copy,sizeof(uint8_t));
    buffer_travel += sizeof(uint8_t);

    to_copy = htons(response->req_id);
    memcpy(buffer_travel,&to_copy,sizeof(uint16_t));
    buffer_travel += sizeof(uint16_t);

    if (response->status_code == SC_OK)
        copy_data_to_buff(response->data, op_to_resp_data_type(response->op_code), buffer_travel);

    return 0;
}

static void assign_proper_data_type(sap_data_type * data, data_type_correspondence data_type_enum, char * buffer){

    switch (data_type_enum) {
        case SAP_SINGLE:
            data->sap_single = *((uint8_t *) buffer);
            break;
        case SAP_SHORT:
            data->sap_short = ntohs(*((uint16_t *)buffer));
            break;
        case SAP_LONG:
            data->sap_long = ntohl(*((uint32_t *)buffer));
            break;
        case SAP_STRING:
            strcpy(data->string, buffer);
            break;
        case SAP_BLANK:
        default:
            data->string[0] = 0;
    }
}

static void copy_data_to_buff(sap_data_type data, data_type_correspondence data_type_enum, char* buffer){

    int to_copy;

    switch (data_type_enum) {
        case SAP_SINGLE:
            to_copy = data.sap_single;
            memcpy(buffer, &to_copy, 1);
            break;
        case SAP_SHORT:
            to_copy = htons(data.sap_short);
            memcpy(buffer, &to_copy, sizeof(uint16_t));
            break;
        case SAP_LONG:
            to_copy = htonl(data.sap_long);
            memcpy(buffer, &to_copy, sizeof(uint32_t));
            break;
        case SAP_STRING:
            strcpy(buffer, data.string);
            break;
        case SAP_BLANK:
        default:
            break;
    }
}

char* sap_error(status_code status_code){
    switch (status_code) {
        case SC_OK:
            return "OK";
        case SC_COMMAND_UNSUPPORTED:
            return "El comando no esta soportado";
        case SC_COMMAND_INVALID_ARGS:
            return "Los argumentos no son validos para este comando";
        case SC_NO_FILTER:
            return "No hay ningun filtro en el proxy";
        case SC_UNAUTHORIZED:
            return "No esta autorizado";
        case SC_VERSION_UNKNOWN:
            return "Version SAP desconocida";
        case SC_INTERNAL_SERVER_ERROR:
            return "Error interno del servidor";
        default:
            return "Error desconocido";
    }
}


data_type_correspondence op_to_req_data_type(op_code op_code){
    switch (op_code) {
        case OP_STATS:
        case OP_SET_TIMEOUT:
        case OP_TOGGLE_FILTER:
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

data_type_correspondence op_to_resp_data_type(op_code op_code){
    switch (op_code) {
        case OP_GET_TIMEOUT:
        case OP_IS_FILTER_WORKING:
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
            size+=sizeof(uint8_t);
            break;
        case SAP_SHORT:
            size+=sizeof(uint16_t);
            break;
        case SAP_LONG:
            size+=sizeof(uint32_t);
            break;
        case SAP_STRING:
            size += data!=NULL?strlen(data):0;
            break;
        case SAP_BLANK:
        default:
            size+=0;
    }

    return size;
}
