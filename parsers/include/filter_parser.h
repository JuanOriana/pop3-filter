#ifndef FILTER_PARSER_H
#define FILTER_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "../../utils/include/buffer.h"



typedef enum{
    FILTER_FIRST_LINE,
    FILTER_MSG,
    FILTER_DOT,
    FILTER_PRE_DOT,
    FILTER_CRLF,
    FILTER_DONE,
    FILTER_ERROR,
}filter_parser_state;

typedef struct{
    size_t          line_size;    
    size_t          crl_state;
    filter_parser_state   state;
    bool first_time;
} filter_parser;


void filter_parser_init(filter_parser * parser);

int filter_parser_is_done(const filter_parser_state state);

filter_parser_state filter_parser_feed(filter_parser * parser, const uint8_t c, buffer * dest, bool skip,buffer * start_msg);

filter_parser_state filter_parser_consume(filter_parser * parser, buffer * src, buffer * dest, bool skip,buffer * start_msg);

#endif