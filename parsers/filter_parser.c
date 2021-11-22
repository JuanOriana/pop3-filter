#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include "./include/filter_parser.h"
#include "../utils/include/logger.h"


#define MAX_MSG_SIZE 512

static const char * crlf_msg = "\r\n.\r\n";

typedef void (*filter_handler_f) ( filter_parser *, char, buffer *, bool parse,buffer *);

static void filter_first_line_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg);
static void filter_msg_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg);
static void filter_dot_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg);
static void filter_crlf_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg);

filter_handler_f filter_handlers[] = {filter_first_line_state,filter_msg_state,filter_dot_state,filter_crlf_state};


void filter_parser_init(filter_parser * parser){
    parser->state = FILTER_FIRST_LINE;
    parser->first_time = true;
    parser->line_size = 0;
    parser->crlf_state = 0;
}

int filter_parser_is_done(const filter_parser_state state){
    return state == FILTER_DONE;
}

filter_parser_state filter_parser_feed(filter_parser * parser, const uint8_t c, buffer * dest, bool parse,buffer * start_msg) {

    if (!(parser->state == FILTER_DONE || parser->state == FILTER_ERROR)){
        if (parser->state > FILTER_ERROR){
            log(ERROR,"Unrecognized state %d", parser->state);
        }
        else{
            filter_handlers[parser->state](parser, c, dest,parse,start_msg);
        }

    }
    if(parser->line_size++ == MAX_MSG_SIZE)
        parser->state = FILTER_ERROR;
    return parser->state;
}

static void filter_first_line_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg){
    if(parse){
        buffer_write(start_msg,c);
    }else{
        buffer_write(dest,c);
    }
    if(c == crlf_msg[1]){
        parser->state = FILTER_MSG;
    }
}

static void filter_msg_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg){
    if(!parse)
        buffer_write(dest, c);
    if(c == crlf_msg[2] && parser->line_size == 0) {
        parser->state = FILTER_DOT;
        parser->crlf_state = 3;
    } else if(c == crlf_msg[0]){
        parser->crlf_state = 1;
    } else if(c == crlf_msg[1]) {
        if(parser->crlf_state == 1) {
            parser->line_size = -1;
            parser->crlf_state = 0;
            if(parse) {
                buffer_write(dest, crlf_msg[0]);
                buffer_write(dest, crlf_msg[1]);
            }
        } else if(!parse) {
            parser->line_size = -1;
            parser->crlf_state = 0;
            buffer_write(dest, crlf_msg[0]);
            buffer_write(dest, crlf_msg[1]);
        } else
            parser->state = FILTER_ERROR;
    } else if(parse)
        buffer_write(dest, c);
}

static void filter_dot_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg){
    if(parse) {
        if(c == crlf_msg[3]) {
            parser->state = FILTER_CRLF;
            parser->crlf_state = 4;
        } else if(c == crlf_msg[2]) {
            buffer_write(dest, c);
            parser->state = FILTER_MSG;
            parser->crlf_state = 0;
        } else
            parser->state = FILTER_ERROR;
    } else {
        parser->state = FILTER_MSG;
        parser->crlf_state = 0;
        if(c == crlf_msg[0]) {
            parser->crlf_state = 1;
        } else if(c == crlf_msg[1]) {
            parser->state = FILTER_ERROR;
        }
        buffer_write(dest, crlf_msg[2]);
        buffer_write(dest, c);
    }
}

static void filter_crlf_state (filter_parser * parser, char c, buffer * dest, bool parse,buffer * start_msg){
    if(c == crlf_msg[4])
        parser->state = FILTER_DONE;
    else
        parser->state = FILTER_ERROR;
}