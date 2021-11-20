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
#include "../utils/include/netutils.h"
#include "../include/args.h"
#include <sys/time.h>
#include <time.h>

#define MAXLINE 2048
#define USER_INPUT_SIZE 100
#define SERVER_VERSION SAP_V_1_0_0
#define AUTH 0
#define TIMEOUT_SEC 5

// For Mac OS
#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

sap_response response;
sap_request  request;
uint16_t req_id;

#define COMMAND_TOTAL_COUNT 11

typedef int (*req_handler_fun_type) ( sap_request *, char *);

typedef struct client_command_t{
    char * name;
    req_handler_fun_type handler;
    char * success_message;
}client_command_t;


/**
 * Muestra todos los comandos habilitados
 */
void help();

/**
 * Funciones genericas para crear requests
 */
void build_blank_request(sap_request * new_request, op_code op_code);
void build_single_request(sap_request * new_request,op_code op_code,uint8_t single_data);
void build_short_request(sap_request * new_request,op_code op_code,uint16_t short_data);
void build_long_request(sap_request * new_request,op_code op_code,uint16_t long_data);

/**
 * Funciones especificas para crear requests. Si da algo < 0 es que hubo un error en los parametros
 */
int historic_connections_req(sap_request * new_request, char * param);
int current_connections_req(sap_request * new_request, char * param);
int transfered_bytes_req(sap_request * new_request, char * param);
int get_buff_size_req(sap_request * new_request, char * param);
int set_buff_size_req(sap_request * new_request, char * param);
int get_timeout_req(sap_request * new_request, char * param);
int set_timeout_req(sap_request * new_request, char * param);
int get_error_req(sap_request * new_request, char * param);
int set_error_req(sap_request * new_request, char * param);
int get_filter_req(sap_request * new_request, char * param);
int set_filter_req(sap_request * new_request, char * param);

/**
 * Maneja la respuesta correspondiente a un request
 */
void handle_response(sap_request request, sap_response new_response, char * prev_message);

client_command_t client_commands[] = {
        {.name="historic", .handler = historic_connections_req, .success_message="La cantidad de conexiones historicas es:"},
        {.name="current", .handler = current_connections_req, .success_message="La cantidad de conexiones actuales es:"},
        {.name="bytes", .handler = transfered_bytes_req, .success_message="La cantidad de bytes transferidos es:"},
        {.name="getbuff", .handler = get_buff_size_req, .success_message="El tamaño del buffer es:"},
        {.name="setbuff", .handler = set_buff_size_req, .success_message="Tamaño del buffer actualizado correctamente"},
        {.name="gettimeout", .handler = get_timeout_req, .success_message="El timeout es:"},
        {.name="settimeout", .handler = set_timeout_req, .success_message="Timeout actualizado correctamente"},
        {.name="geterror", .handler = get_error_req, .success_message="La salida de error en filter es:"},
        {.name="seterror", .handler = get_error_req, .success_message="La salida de error en filter fue actualizada"},
        {.name="getfilter", .handler = get_filter_req, .success_message="El filtro utlizado es:"},
        {.name="setfilter", .handler = set_filter_req, .success_message="Filtro actualizado correctamente"}
};

int go_on = 1;

int main(int argc, const char* argv[]) {

    if (argc != 3){
        fprintf(stderr,"Uso: client <manag_addr> <manag_port>");
        exit(EXIT_FAILURE);

    }

    int sockfd, valid_param,port, ip_type;
    struct sockaddr_in servaddr;
    struct sockaddr_in6 servaddr6;
    char buffer_in[MAXLINE], buffer_out[MAXLINE], user_input[USER_INPUT_SIZE], *command_name, *param;

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&servaddr6, 0, sizeof(servaddr6));

    if ((port = htons(atoi(argv[2]))) <= 0){
        fprintf(stderr,"Puerto invalido");
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr.s_addr) > 0)
    {
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = port;
        ip_type = ADDR_IPV4;
    }
    else if(inet_pton(AF_INET6, argv[1], &servaddr6.sin6_addr) > 0){
        servaddr6.sin6_family = AF_INET6;
        servaddr6.sin6_port = port;
        ip_type = ADDR_IPV6;
    }

    // Creating socket file descriptor
    if ((sockfd = socket(ip_type == ADDR_IPV4 ? AF_INET:AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        log(ERROR,"Failed manager client socket creation");
        exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        log(ERROR,"Failed manager client setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while(go_on) {
        command_name = param = NULL;
        printf("\033[0;32m");
        printf("sap_client >> ");
        printf("\033[0m");
        memset(user_input, 0, USER_INPUT_SIZE);
        fgets(user_input,USER_INPUT_SIZE,stdin);
        // Remuevo \r\n o \n del final
        user_input[strcspn(user_input, "\r\n")] = 0;
        command_name = strtok(user_input, " ");

        if (command_name != NULL) {
            param = strtok(NULL, " ");
        }

        //Special case for help
        if (strcmp(command_name, "help") == 0){
            help();
            continue;
        }

        int i;
        for (i =0; i < COMMAND_TOTAL_COUNT; i++){
            if (strcmp(command_name,client_commands[i].name) == 0){
                valid_param = client_commands[i].handler(&request,param);
                break;
            }
        }
        if (i == COMMAND_TOTAL_COUNT){
            printf("Comando invalido, vea la lista de comandos ingresando 'help'\n");
            continue;
        }
        if (valid_param < 0){
            printf("Parametro invalido para el comando %s\n",command_name);
            continue;
        }

        int req_size;
        ssize_t n;
        socklen_t len;

        memset(buffer_in, 0, MAXLINE);
        memset(buffer_out, 0, MAXLINE);

        if (sap_request_to_buffer(buffer_out, &request, &req_size) < 0) {
            log(ERROR, "Error converting request to buffer");
        }

        if (sap_request_to_buffer(buffer_out, &request, &n) < 0) {
            log(ERROR, "Error converting request to buffer");
        }

        if (ip_type == ADDR_IPV4) {
            sendto(sockfd, buffer_out, n,
                   MSG_CONFIRM, (const struct sockaddr *) &servaddr,
                   sizeof(servaddr));

            n = recvfrom(sockfd, (char *) buffer_in, MAXLINE,
                         MSG_WAITALL, (struct sockaddr *) &servaddr,
                         &len);
        }else{
            sendto(sockfd, buffer_out, n,
                   MSG_CONFIRM, (const struct sockaddr *) &servaddr6,
                   sizeof(servaddr6));

            n = recvfrom(sockfd, (char *) buffer_in, MAXLINE,
                         MSG_WAITALL, (struct sockaddr *) &servaddr6,
                         &len);
        }

        // Timeout
        if (n < 0)
        {
            printf("\033[0;31m");
            printf("No obtuvimos respuesta del servidor, puede ser que este lento pero por si las dudas verifique que ingreso correctamente"
                   "la direccion y el puerto del manager.\n");
            printf("\033[0m");
            continue;
        }

        if (sap_buffer_to_response(buffer_in, &response) < 0) {
            log(ERROR, "Error converting buffer to response");
            continue;
        }

        handle_response(request,response,client_commands[i].success_message);
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

void build_string_request(sap_request * new_request,op_code op_code, char* string ){
    build_blank_request(new_request,op_code);
    strcpy(new_request->data.string,string);
}

int historic_connections_req(sap_request * new_request, char * param){
    build_single_request(new_request,OP_STATS,0);
    return 0;
}

int current_connections_req(sap_request * new_request, char * param){
    build_single_request(new_request,OP_STATS,1);
    return 0;
}

int transfered_bytes_req(sap_request * new_request, char * param){
    build_single_request(new_request,OP_STATS,2);
    return 0;
}

int get_buff_size_req(sap_request * new_request, char * param){
    build_blank_request(new_request,OP_GET_BUFF_SIZE);
    return 0;
}

int set_buff_size_req(sap_request * new_request, char * param){
    if (param == NULL){
        return -1;
    }
    int short_data = atoi(param);
    if (short_data <= 0 || short_data > UINT16_MAX )
        return -1;
    build_short_request(new_request,OP_SET_BUFF_SIZE,(uint16_t )short_data);
    return 0;
}

int get_timeout_req(sap_request * new_request, char * param){
    build_blank_request(new_request,OP_GET_TIMEOUT);
    return 0;
}

int set_timeout_req(sap_request * new_request, char * param){
    if (param == NULL){
        return -1;
    }
    int single_data = atoi(param);
    if (single_data <= 0 || single_data > UINT8_MAX )
        return -1;
    build_single_request(new_request,OP_SET_TIMEOUT,(uint8_t)single_data);
    return 0;
}

int get_error_req(sap_request * new_request, char * param){
    build_blank_request(new_request,OP_GET_ERROR_FILE);
    return 0;
}

int set_error_req(sap_request * new_request, char * param){
    if (param == NULL){
        return -1;
    }
    build_string_request(new_request,OP_SET_ERROR_FILE,param);
    return 0;
}

int get_filter_req(sap_request * new_request, char * param){
    build_blank_request(new_request,OP_GET_FILTER);
    return 0;
}

int set_filter_req(sap_request * new_request, char * param){
    if (param == NULL){
        return -1;
    }
    build_string_request(new_request,OP_SET_FILTER,param);
    return 0;
}

void handle_response(sap_request request, sap_response new_response, char * prev_message){
    if (request.req_id != new_response.req_id){
        printf("\033[0;31m");
        printf("Error: La respuesta recibida no corresponde al pedido efectuado.\n");
        printf("\033[0m");
        return;
    }
    if (new_response.status_code != 0){
        printf("\033[0;31m");
        printf("Error: %s.\n", sap_error(new_response.status_code));
        printf("\033[0m");
        return;
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
    printf("\n");

}

void help(){
    printf("\nAqui la lista de comandos habilitados para el manejo de SAP, van todos en minuscula\n"
           "\thelp - Devuelve la lista de comandos disponibles.\n"
           "\thistoric - Devuelve la cantidad de conexiones historicas.\n"
           "\tcurrent - Devuelve la cantidad de conexiones actuales.\n"
           "\tbytes - Devuelve la cantidad de bytes transferidos.\n"
           "\tgetbuff - Devuelve el tamaño del buffer utilizado.\n"
           "\tsetbuff <buffsize> - Cambia el tamaño del buffer utilizado.\n"
           "\tgettimeout - Devuelve el timeout utilizado.\n"
           "\tsettimeout <timeout> - Cambia el timeout utilizado.\n"
           "\tgeterror - Devuelve el file hacia donde se redirige el error.\n"
           "\tseterror <errfile> - Cambia el file hacia donde se redirige el error.\n"
           "\tgetfilter - Devuelve el filtro que usa el transform.\n"
           "\tsetfilter <filter> - Cambia el filtro que usa el transform.\n\n");
}