
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "./include/command_response_parser.h"
#include "../utils/include/logger.h"
#include "string.h"


static const char * positive_indicator_msg        = "+OK";
static const int    positive_indicator_msg_size    = 3;
static const char * negative_indicator_msg        = "-ERR";
static const int    negative_indicator_msg_size    = 4;
static const char * crlf_inline_msg               = "\r\n";
static const int    crlf_inline_msg_size           = 2;
static const char * crlf_multi_msg            = "\r\n.\r\n";
static const int    crlf_multi_msg_size        = 5;


void command_response_parser_init(command_response_parser * parser) {
    parser->state     = RESPONSE_INIT;
    parser->line_size  = 0;
    parser->crlf_state = 0;
    parser->command_interest = CMD_RETR;
}

command_response_state command_response_parser_feed(command_response_parser * parser, const char c, command_instance * command_to_respond) {
    command_instance * current_command = command_to_respond;
    if(current_command == NULL)
        parser->state = RESPONSE_ERROR;

    switch(parser->state) {
        case RESPONSE_INIT:
            if(c == positive_indicator_msg[0])
                parser->state = RESPONSE_INDICATOR_POS;
            else if(c == negative_indicator_msg[0])
                parser->state = RESPONSE_INDICATOR_NEG;
            else
                parser->state = RESPONSE_ERROR;
            break;

        case RESPONSE_INDICATOR_POS:
            if(c != positive_indicator_msg[parser->line_size])
                parser->state = RESPONSE_ERROR;
            else if(parser->line_size == positive_indicator_msg_size - 1) {
                current_command->indicator = true;
                parser->crlf_state = 0;
                parser->state = RESPONSE_INDICATOR_MSG;
            }
            break;

        case RESPONSE_INDICATOR_NEG:
            if(c != negative_indicator_msg[parser->line_size])
                parser->state = RESPONSE_ERROR;
            else if(parser->line_size == negative_indicator_msg_size - 1) {
                current_command->indicator = false;
                parser->crlf_state = 0;
                parser->state = RESPONSE_INDICATOR_MSG;
            }
            break;

        case RESPONSE_INDICATOR_MSG:
            // Read message till \r, then a \n is expected (always)
            if(c == crlf_inline_msg[0]) {
                parser->crlf_state = 1;
                parser->state = RESPONSE_INLINE_CRLF;
            }
            break;

        case RESPONSE_INLINE_CRLF:
            // I expect to complete a \r\n, then i evaluate if a multiline response follows or not
            if(c == crlf_inline_msg[parser->crlf_state++]) {
                if(parser->crlf_state == crlf_inline_msg_size) {
                    // -1 because its incremented at the end of the
                    parser->line_size     = -1;
                    parser->crlf_state    =  2;
                    // If is multiline AND we have a positive response, we continue, else we are absolutely done.
                    if(current_command->indicator && current_command->type == parser->command_interest && current_command->is_multi)
                        parser->state    = RESPONSE_INTEREST;
                    else if(current_command->indicator && current_command->is_multi)
                        parser->state    = RESPONSE_BODY;
                    else {
                        parser->crlf_state    =  0;
                        parser->state    = RESPONSE_INIT;
                    }
                }
            } else
                parser->state = RESPONSE_ERROR;
            break;

        case RESPONSE_BODY:
            if (c == crlf_multi_msg[0]){
                parser->crlf_state = 1;
            }
            else if(c == crlf_multi_msg[1]) {
                if(parser->crlf_state == 1) {
                    parser->line_size  = -1;
                    parser->crlf_state = 2;
                } else
                    parser->state = RESPONSE_ERROR;
            }
            else if(c == crlf_multi_msg[parser->crlf_state] && parser->crlf_state == 2) {
                parser->state     = RESPONSE_MULTILINE_CRLF;
                parser->crlf_state = 3;
            }
            else{
                parser->crlf_state = 0;
            }
            break;

        case RESPONSE_MULTILINE_CRLF:
            if(c == crlf_multi_msg[parser->crlf_state++]) {
                if(parser->crlf_state == crlf_multi_msg_size) {
                    parser->state     = RESPONSE_INIT;
                    parser->line_size  = -1;
                    parser->crlf_state = 0;
                }
            } else if(parser->crlf_state == crlf_multi_msg_size - 1) {
                parser->state     = RESPONSE_BODY;
                parser->crlf_state = 0;
            } else
                parser->state = RESPONSE_ERROR;
            break;

        case RESPONSE_INTEREST:
            parser->state = RESPONSE_BODY;
            if (c == crlf_multi_msg[0]){
                parser->crlf_state = 1;
            }
            else if(c == crlf_multi_msg[1]) {
                if(parser->crlf_state == 1) {
                    parser->line_size  = -1;
                    parser->crlf_state = 2;
                } else
                    parser->state = RESPONSE_ERROR;
            }
            else if(c == crlf_multi_msg[parser->crlf_state] && parser->crlf_state == 2) {
                parser->state     = RESPONSE_MULTILINE_CRLF;
                parser->crlf_state = 3;
            }
            else{
                parser->crlf_state = 0;
            }
            break;

        case RESPONSE_ERROR:
            break;

        default:
            log(ERROR,"Response parser not reconize state: %d", parser->state);
    }
    if(parser->line_size++ == MAX_MSG_SIZE)
        parser->state = RESPONSE_ERROR;
    return parser->state;
}

command_response_state command_response_parser_consume(command_response_parser * parser, buffer* buffer, command_instance * command_to_respond, bool * errored) {
    command_response_state state = parser->state;
    *errored = false;

    while(buffer_can_read(buffer)) {
        const uint8_t c = buffer_read(buffer);
        state = command_response_parser_feed(parser, c, command_to_respond);
        if(state == RESPONSE_ERROR) {
            *errored = true;
            break;
        }
    }
    return state;
}

command_response_state command_response_parser_consume_until(command_response_parser * parser, buffer* buffer,
                                                             command_instance * command_to_respond, bool interested, bool to_new_commanc, bool * errored) {
    command_response_state state = parser->state;
    *errored = false;
    if(to_new_commanc && state == RESPONSE_INIT)
        return state;

    while(buffer_can_read(buffer)) {
        const uint8_t c = buffer_read(buffer);
        state = command_response_parser_feed(parser, c, command_to_respond);
        if(state == RESPONSE_ERROR) {
            *errored = true;
            break;
        } else if((state == RESPONSE_INTEREST && interested) || (state == RESPONSE_INIT && to_new_commanc))
            break;
    }
    return state;
}

