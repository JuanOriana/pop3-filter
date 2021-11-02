#ifndef HELLO_PARSER_H
#define HELLO_PARSER_H

#include <stdint.h>
#include <buffer.h>

typedef enum
{
    HELLO_INIT_INDICATOR,
    HELLO_MESSAGE,
    HELLO_CRLF,
    HELLO_FINISHED_CORRECTLY,
    HELLO_FAILED,
} hello_state;

typedef struct hello_parser
{
    /** permite al usuario del parser almacenar sus datos */
    size_t msg_size;

    hello_state current_state;

} hello_parser;

hello_state parse_hello(hello_parser *parser, buffer *read_buffer);

bool hello_finished(const hello_state state);

#endif