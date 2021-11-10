#ifndef RESPONSE_PARSER_H
#define RESPONSE_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "../../utils/include/buffer.h"
#include "./command_parser.h"


typedef enum command_response_state {
    RESPONSE_INIT,
    RESPONSE_INDICATOR_NEG,
    RESPONSE_INDICATOR_POS,
    RESPONSE_INDICATOR_MSG,
    RESPONSE_BODY,
    RESPONSE_INLINE_CRLF,
    RESPONSE_MULTILINE_CRLF,
    RESPONSE_ERROR,
} command_response_state;

typedef struct command_response_parser {
    size_t        line_size;
    size_t        crlf_state; //0 NONE, 1 \r READ, 2 \n READ. 3 \. READ, 4 \r READ, 5 \n READ
    bool          is_starting_body; //0 NONE, 1 \r READ, 2 \n READ. 3 \. READ, 4 \r READ, 5 \n READ
    command_t     command_interest;
    command_response_state state;
} command_response_parser;

/** Inicializa el parser */
void command_response_parser_init(command_response_parser * parser);

/** Entrega un byte al parser. retorna true si se llego al final  */
command_response_state command_response_parser_feed(command_response_parser * parser, const char c, command_instance* command_to_respond);

/**
 * Por cada elemento del buffer llama a `responseParserFeed' hasta que
 * el parseo se encuentra completo o se requieren mas bytes.
 *
 * @param errored parametro de salida. Si es diferente de NULL se deja dicho
 *   si el parsing se debió a una condición de error
 */
command_response_state command_response_parser_consume(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read, command_instance* command_to_respond, bool * errored);


command_response_state command_response_parser_consume_until(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read, command_instance* command_to_respond,
                                         bool interested, bool to_new_command, bool * errored);

#endif
