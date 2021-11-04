#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "../../utils/include/buffer.h"

#define SIZE_OF_CMD_TYPES  9

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
} command_t;

typedef struct command {
    command_t    type;
    bool         is_multi;
    bool         indicator;
    void *       data;
    struct command *    next;
} command;

typedef enum command_state {
    COMMAND_TYPE,
    COMMAND_ARGS,
    COMMAND_CRLF,
    COMMAND_ERROR,
} command_state;

typedef struct command_parser {
    int line_size;
    int state_size;
    int args_size;
    int  invalid_size;
    bool   invalid_type[SIZE_OF_CMD_TYPES];
    command_state state;
    command current_command;
} command_parser;

/** inicializa el parser */
void command_parser_init(command_parser * parser);

/** entrega un byte al parser. retorna true si se llego al final  */
command_state command_parser_feed(command_parser * parser, const char c, command * commands, bool * finished);

/**
 * por cada elemento del buffer llama a `commandParserFeed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
command_state command_parser_consume(command_parser * parser,
                                     buffer* buffer, command * commands, bool pipelining, bool * has_command_changed);

char * ger_user(const command command);

void command_delete(command * command);

#endif