#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "../../utils/include/buffer.h"

#define MAX_MSG_SIZE 512
#define MAX_ARG_SIZE 40
#define SIZE_OF_CMD_TYPES  12

typedef enum command_t {
    CMD_NOT_RECOGNIZED     = -1,
    CMD_USER               =  0,
    CMD_PASS               =  1,
    CMD_APOP               =  2,
    CMD_RETR               =  3,
    CMD_LIST               =  4,
    CMD_CAPA               =  5,
    CMD_TOP                =  6,
    CMD_UIDL               =  7,
    CMD_QUIT               =  8,
    CMD_DELE               =  9,
    CMD_NOOP               =  10,
    CMD_STAT               =  11,
} command_t;

typedef struct command_instance {
    command_t    type;
    // is_multi e indicator sirven mas adelante para el manejo de su response
    bool         is_multi;
    bool         indicator;
    void *       data;
} command_instance;

typedef enum command_state {
    COMMAND_TYPE,
    COMMAND_ARGS,
    COMMAND_CRLF,
    COMMAND_ERROR,
} command_state;

typedef struct command_parser {
    int                 line_size;
    int                 crlf_state;  //0 NONE, 1 \r READ, 2 \n READ
    int                 state_size;
    int                 args_size;
    // Asumo que todos los comandos son posibles y voy descartando segun encuentro incompatibilidades
    int                 invalid_size;
    bool                invalid_type[SIZE_OF_CMD_TYPES];
    command_state       state;
    command_instance    current_command;
    bool                is_expecting_new_arg;
} command_parser;

/**
 * Inicializa el parser
 */
void command_parser_init(command_parser * parser);

/**
 * Entrega un char al parser. Deja a finished en true si se llego al final
 */
command_state command_parser_feed(command_parser * parser, const char c, bool * finished);

/**
 * Consume un los chars de un buffer
 * Finaliza si:
 *  a) Quiero manejar pipelining y llegue al final de un comando
 *  b) Consumi todo
 */
command_state command_parser_consume(command_parser * parser, buffer* buffer, bool pipelining, bool * finished,size_t * n_consumed);

/**
 * Retorna el usuario, dado el comando que lo leyo
*/
char * get_user(command_instance command);

#endif