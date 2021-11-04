#ifndef HELLO_PARSER_H
#define HELLO_PARSER_H

#include <stdint.h>
#include "../../utils/include/buffer.h"

typedef enum
{
    // "+OK"
    HELLO_INIT_INDICATOR,

    // El mensaje definido por el server
    HELLO_MESSAGE,

    // "\r\n"
    HELLO_CRLF,

    // Termino bien
    HELLO_FINISHED_CORRECTLY,

    // Termino mal
    HELLO_FAILED,

} hello_state;

typedef struct hello_parser
{
    // indice del caracter actual
    size_t index;

    // estado actual del parser
    hello_state current_state;

} hello_parser;

/** Inicializa el parser **/
void hello_parser_init(hello_parser *parser);

/**
 *
 * Itera por el read_buffer hasta que complete su parseo o ocurra algun error.
 *
 * En cada iteracion llama a hello_parser_input.
 *
 * Retorna el estado en el que termino el parser, HELLO_FINISHED_CORRECTLY (termino correctamente)
 * o HELLO_FAILED (fallo durante el parseo).
 *
 *  **/
hello_state parse_hello(hello_parser *parser, buffer *read_buffer);

/** Valida que el char del buffer coincida con algun estado correcto del server POP3 **/
hello_state hello_parser_input(hello_parser *parser, uint8_t readed_char);

/** Devuelve si el parser termino con el parseo o debe continuar **/
bool hello_finished(const hello_state state);

#endif