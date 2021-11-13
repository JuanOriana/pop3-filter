#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "./include/filter_parser.h"
#include "../utils/include/logger.h"


#define MAX_MSG_SIZE 512

static const char * crlfMsg = "\r\n.\r\n";


void filter_parser_init(filter_parser * parser){
    parser->state = FILTER_MSG;
    parser->line_size = 0;
    parser->state_size = 0;
}

int filter_parser_is_done(const filter_parser_state state, bool * errrored){
    bool ret = true;

    switch (state)
    {
    case FILTER_ERROR:
        if(errrored != 0){
            *errrored = true;
        }
        break;
    case FILTER_DONE:
        ret = true;
        break;
    default:
        ret = false;
        break;
    }

    return ret;
}

filter_parser_state filter_parser_feed(filter_parser * parser, const uint8_t c, buffer * dest, bool skip) {
    switch(parser->state) {
        case FILTER_MSG:
            if(!skip)
                buffer_write(dest, c);
            if(c == crlfMsg[2] && parser->line_size == 0) {
                parser->state = FILTER_DOT;
                parser->state_size = 3;
            } else if(c == crlfMsg[0]) 
                parser->state_size = 1;
            else if(c == crlfMsg[1]) {
                if(parser->state_size == 1) {
                    parser->line_size = -1;
                    parser->state_size = 0;
                    if(skip) {
                        buffer_write(dest, crlfMsg[0]);
                        buffer_write(dest, crlfMsg[1]);
                    }
                } else if(!skip) {
                    parser->line_size = -1;
                    parser->state_size = 0;
                    buffer_write(dest, crlfMsg[0]);
                    buffer_write(dest, crlfMsg[1]);
                } else
                    parser->state = FILTER_ERROR;
            } else if(skip)
                buffer_write(dest, c);
            break;

        case FILTER_DOT:
            if(skip) {
                if(c == crlfMsg[3]) {
                    parser->state = FILTER_CRLF;
                    parser->state_size = 4;
                } else if(c == crlfMsg[2]) {
                    buffer_write(dest, c);
                    parser->state = FILTER_MSG;
                    parser->state_size = 0;
                } else
                    parser->state = FILTER_ERROR;
            } else {
                parser->state = FILTER_MSG;
                parser->state_size = 0;
                if(c == crlfMsg[0]) {
                    parser->state_size = 1;
                } else if(c == crlfMsg[1]) {
                    parser->state = FILTER_ERROR;
                }
                buffer_write(dest, crlfMsg[2]);
                buffer_write(dest, c);
            }
            break;

        case FILTER_CRLF:
            if(c == crlfMsg[4])
                parser->state = FILTER_DONE;
            else
                parser->state = FILTER_ERROR;
            break;

        case FILTER_DONE:
        case FILTER_ERROR:
            // nada que hacer, nos quedamos en este estado
            break;
        default:
            log(ERROR,"Body pop3 parser not reconize state: %d", parser->state);
    }
    if(parser->line_size++ == MAX_MSG_SIZE)
        parser->state = FILTER_ERROR;
    return parser->state;
}

filter_parser_state filter_parser_consume(filter_parser * parser, buffer * src, buffer * dest, bool skip, bool * errored) {
    filter_parser_state state = parser->state;
    *errored = false;
    size_t size;
    uint8_t *ptr = buffer_write_ptr(dest, &size);

    while(buffer_can_read(src) && size >= 2) {
        const uint8_t c = buffer_read(src);
        state = filter_parser_feed(parser, c, dest, skip);
        if(filter_parser_is_done(state, errored)) {
            break;
        } else
            buffer_write_ptr(dest, &size);
    }
    return state;
}