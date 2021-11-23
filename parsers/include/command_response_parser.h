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
    int                     line_size;
    int                     crlf_state; //0 NONE, 1 \r READ, 2 \n READ. 3 \. READ, 4 \r READ, 5 \n READ
    bool                    is_starting_body;       // Avisa cuando comienza la primera linea del cuerpo
    bool                    is_pipelining_possible; // Marca si una linea ya no coincide con el string PIPELINING
    bool                    includes_pipelining;    // Marca si en ALGUNA linea se vio PIPELINING
    command_t               command_interest;
    command_response_state  state;
} command_response_parser;

/**
 * Inicializa el parser
 */
void command_response_parser_init(command_response_parser * parser);

/**
 * Entrega un char al parser. Vuelve a RESPONSE_INIT si finalizo bien y RESPONSE_ERROR si finalizo mal
 */
command_response_state command_response_parser_feed(command_response_parser * parser, const char c, command_instance* command_to_respond);

/**
 * Consume un los chars de un buffer
 * Finaliza si:
 *  a) Termine de leer la respuesta (bien o con error)
 *  b) Consumi todo el buffer
 */
command_response_state command_response_parser_consume(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read, command_instance* command_to_respond, bool * errored);

/**
 * Consume los chars de un buffer evaluando intereses
 */
command_response_state command_response_parser_consume_until(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read, command_instance* command_to_respond,
                                         bool interested, bool to_new_command, bool * errored);

#endif
