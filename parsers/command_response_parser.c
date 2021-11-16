
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
static const char * pipelining_string = "PIPELINING";
static const int    pipelining_string_size        = 10;

typedef void (*command_response_handler_f) ( command_response_parser *, char, command_instance *);

static void command_response_init (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command);
static void command_response_indicator_pos (command_response_parser * parser, const char c, command_instance * current_command);
static void command_response_indicator_neg (command_response_parser * parser, const char c, command_instance * current_command);
static void command_response_indicator_msg (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command);
static void command_response_inline_crlf (command_response_parser * parser, const char c, command_instance * current_command);
static void command_response_body (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command);
static void command_response_multiline_crlf (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command);
static void command_response_error (command_response_parser * parser, __attribute__((unused)) const char c, __attribute__((unused)) command_instance * current_command);

command_response_handler_f command_response_handlers[] = {command_response_init, command_response_indicator_neg, command_response_indicator_pos,
            command_response_indicator_msg, command_response_body, command_response_inline_crlf, command_response_multiline_crlf, command_response_error};

void command_response_parser_init(command_response_parser * parser) {
    parser->state     = RESPONSE_INIT;
    parser->line_size  = 0;
    parser->crlf_state = 0;
    parser->is_starting_body = false;
    parser->includes_pipelining = false;
    parser->is_pipelining_possible = true;
    parser->command_interest = CMD_RETR;
}

command_response_state command_response_parser_feed(command_response_parser * parser, const char c, command_instance * command_to_respond) {
    command_instance * current_command = command_to_respond;
    if(current_command == NULL){
        parser->state = RESPONSE_ERROR;
        log(ERROR, "command null");
    }

    if(parser->state > RESPONSE_ERROR) {
        log(ERROR,"Response parser not reconize state: %d", parser->state);
    }
    else {
        command_response_handlers[parser->state](parser, c, current_command);
    }
/*
    switch(parser->state) {
        case RESPONSE_INIT:
            ///
            if(c == positive_indicator_msg[0])
                parser->state = RESPONSE_INDICATOR_POS;
            else if(c == negative_indicator_msg[0])
                parser->state = RESPONSE_INDICATOR_NEG;
            else
                parser->state = RESPONSE_ERROR;///
            command_response_init(parser, c, current_command);
            break;

        case RESPONSE_INDICATOR_POS:
            ///
            if(c != positive_indicator_msg[parser->line_size])
                parser->state = RESPONSE_ERROR;
            else if(parser->line_size == positive_indicator_msg_size - 1) {
                current_command->indicator = true;
                parser->crlf_state = 0;
                parser->state = RESPONSE_INDICATOR_MSG;
            }///
            command_response_indicator_pos(parser, c, current_command);
            break;

        case RESPONSE_INDICATOR_NEG:
            ///
            if(c != negative_indicator_msg[parser->line_size])
                parser->state = RESPONSE_ERROR;
            else if(parser->line_size == negative_indicator_msg_size - 1) {
                current_command->indicator = false;
                parser->crlf_state = 0;
                parser->state = RESPONSE_INDICATOR_MSG;
            }///
            command_response_indicator_neg(parser, c, current_command);
            break;

        case RESPONSE_INDICATOR_MSG:
            ///
            if(c == crlf_inline_msg[0]) {
                parser->crlf_state = 1;
                parser->state = RESPONSE_INLINE_CRLF;
            }///
            command_response_indicator_msg(parser, c, current_command);
            break;

        case RESPONSE_INLINE_CRLF:
            ///
            if(c == crlf_inline_msg[parser->crlf_state++]) {
                if(parser->crlf_state == crlf_inline_msg_size) {
                    // -1 because its incremented at the end of the run
                    parser->line_size     = -1;
                    parser->crlf_state    =  2;
                    // If is multiline AND we have a positive response, we continue, else we are absolutely done.
                    if(current_command->indicator && current_command->is_multi) {
                        parser->is_starting_body = true;
                        parser->is_pipelining_possible = true;
                        parser->state = RESPONSE_BODY;
                    }
                    else {
                        parser->crlf_state    =  0;
                        parser->state    = RESPONSE_INIT;
                    }
                }
            } else
                parser->state = RESPONSE_ERROR;///
            command_response_inline_crlf(parser, c, current_command);
            break;

        case RESPONSE_BODY:
            ///
            parser->is_starting_body = false;
            // CRLF HANDLING
            if (c == crlf_multi_msg[0]){
                parser->crlf_state = 1;
            }
            else if(c == crlf_multi_msg[1]) {
                if(parser->crlf_state == 1) {
                    parser->crlf_state = 2;
                    parser->is_pipelining_possible = true;
                    parser->line_size = -1;
                } else
                    parser->state = RESPONSE_ERROR;
            }
            else if(c == crlf_multi_msg[parser->crlf_state] && parser->crlf_state == 2) {
                parser->state     = RESPONSE_MULTILINE_CRLF;
                parser->crlf_state = 3;
            }
            // We are not parsing CRLF
            else{
                parser->crlf_state = 0;
                if(!parser->includes_pipelining && parser->is_pipelining_possible && toupper(c) == pipelining_string[parser->line_size]){
                    if (parser->line_size == pipelining_string_size-1){
                        parser->includes_pipelining = true;
                    }
                }
                else{
                    parser->is_pipelining_possible = false;
                }
            }///
            command_response_body(parser, c, current_command);
            break;

        case RESPONSE_MULTILINE_CRLF:
            ///
            if(c == crlf_multi_msg[parser->crlf_state++]) {
                if(parser->crlf_state == crlf_multi_msg_size) {
                    parser->state     = RESPONSE_INIT;
                    parser->line_size  = -1;
                    parser->crlf_state = 0;
                }
            } else if(parser->crlf_state == crlf_multi_msg_size - 1) {
                parser->is_pipelining_possible = true;
                parser->line_size  = -1;
                parser->crlf_state = 0;
                parser->state     = RESPONSE_BODY;
            } else
                parser->state = RESPONSE_ERROR;///
            command_response_multiline_crlf(parser, c, current_command);
            break;

        case RESPONSE_ERROR:
            break;

        default:
            log(ERROR,"Response parser not reconize state: %d", parser->state);
    }
*/
    if(parser->line_size++ == MAX_MSG_SIZE)
        parser->state = RESPONSE_ERROR;
    return parser->state;
}

command_response_state command_response_parser_consume(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read, command_instance * command_to_respond, bool * errored) {
    command_response_state state = parser->state;
    *errored = false;

    for(int i = 0; i < n_to_read; i++) {
        const uint8_t c = char_buffer[i];
        state = command_response_parser_feed(parser, c, command_to_respond);
        if(state == RESPONSE_ERROR) {
            *errored = true;
            break;
        }
    }
    return state;
}

command_response_state command_response_parser_consume_until(command_response_parser * parser, uint8_t* char_buffer, size_t n_to_read,
                                                             command_instance * command_to_respond, bool interested, bool to_new_command, bool * errored) {
    command_response_state state = parser->state;
    *errored = false;
    // if(to_new_commanc && state == RESPONSE_INIT)
    //     return state;
    
    for(int i = 0; i < n_to_read; i++) {
        const uint8_t c = char_buffer[i];
        state = command_response_parser_feed(parser, c, command_to_respond);
        if(state == RESPONSE_ERROR) {
            *errored = true;
            break;
        } else if((parser->is_starting_body && interested) || (state == RESPONSE_INIT && to_new_command))
            break;
    }
    return state;
}

static void command_response_init (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command) {
    log(DEBUG, "EStoy en init: %d", parser->state);
    if(c == positive_indicator_msg[0])
        parser->state = RESPONSE_INDICATOR_POS;
    else if(c == negative_indicator_msg[0])
        parser->state = RESPONSE_INDICATOR_NEG;
    else
        parser->state = RESPONSE_ERROR;
}

static void command_response_indicator_pos (command_response_parser * parser, const char c, command_instance * current_command) {
    log(DEBUG, "EStoy en indicator pos: %d", parser->state);
    if(c != positive_indicator_msg[parser->line_size])
        parser->state = RESPONSE_ERROR;
    else if(parser->line_size == positive_indicator_msg_size - 1) {
        current_command->indicator = true;
        parser->crlf_state = 0;
        parser->state = RESPONSE_INDICATOR_MSG;
    }
}

static void command_response_indicator_neg (command_response_parser * parser, const char c, command_instance * current_command) {
    log(DEBUG, "EStoy en indicator neg: %d", parser->state);
    if(c != negative_indicator_msg[parser->line_size])
        parser->state = RESPONSE_ERROR;
    else if(parser->line_size == negative_indicator_msg_size - 1) {
        current_command->indicator = false;
        parser->crlf_state = 0;
        parser->state = RESPONSE_INDICATOR_MSG;
    }
}

static void command_response_indicator_msg (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command) {
    log(DEBUG, "EStoy en indicator msg: %d", parser->state);
    // Read message till \r, then a \n is expected (always)
    if(c == crlf_inline_msg[0]) {
        parser->crlf_state = 1;
        parser->state = RESPONSE_INLINE_CRLF;
    }
}

static void command_response_inline_crlf (command_response_parser * parser, const char c, command_instance * current_command) {
    log(DEBUG, "EStoy en inline crlf: %d", parser->state);
    // I expect to complete a \r\n, then i evaluate if a multiline response follows or not
    if(c == crlf_inline_msg[parser->crlf_state++]) {
        if(parser->crlf_state == crlf_inline_msg_size) {
            // -1 because its incremented at the end of the run
            parser->line_size     = -1;
            parser->crlf_state    =  2;
            // If is multiline AND we have a positive response, we continue, else we are absolutely done.
            if(current_command->indicator && current_command->is_multi) {
                parser->is_starting_body = true;
                parser->is_pipelining_possible = true;
                parser->state = RESPONSE_BODY;
            }
            else {
                parser->crlf_state    =  0;
                parser->state    = RESPONSE_INIT;
            }
        }
    } else
        parser->state = RESPONSE_ERROR;
}

static void command_response_body (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command) {
    log(DEBUG, "EStoy en response body: %d", parser->state);
    parser->is_starting_body = false;
    // CRLF HANDLING
    if (c == crlf_multi_msg[0]){
        parser->crlf_state = 1;
    }
    else if(c == crlf_multi_msg[1]) {
        if(parser->crlf_state == 1) {
            parser->crlf_state = 2;
            parser->is_pipelining_possible = true;
            parser->line_size = -1;
        } else
            parser->state = RESPONSE_ERROR;
    }
    else if(c == crlf_multi_msg[parser->crlf_state] && parser->crlf_state == 2) {
        parser->state     = RESPONSE_MULTILINE_CRLF;
        parser->crlf_state = 3;
    }
    // We are not parsing CRLF
    else{
        parser->crlf_state = 0;
        if(!parser->includes_pipelining && parser->is_pipelining_possible && toupper(c) == pipelining_string[parser->line_size]){
            if (parser->line_size == pipelining_string_size-1){
                parser->includes_pipelining = true;
            }
        }
        else{
            parser->is_pipelining_possible = false;
        }
    }
}

static void command_response_multiline_crlf (command_response_parser * parser, const char c, __attribute__((unused)) command_instance * current_command) {
    log(DEBUG, "EStoy en multiline crlf: %d", parser->state);
    if(c == crlf_multi_msg[parser->crlf_state++]) {
        if(parser->crlf_state == crlf_multi_msg_size) {
            parser->state     = RESPONSE_INIT;
            parser->line_size  = -1;
            parser->crlf_state = 0;
        }
    } else if(parser->crlf_state == crlf_multi_msg_size - 1) {
        parser->is_pipelining_possible = true;
        parser->line_size  = -1;
        parser->crlf_state = 0;
        parser->state     = RESPONSE_BODY;
    } else
        parser->state = RESPONSE_ERROR;
}

static void command_response_error (command_response_parser * parser, __attribute__((unused)) const char c, __attribute__((unused)) command_instance * current_command) {
    log(ERROR, "Response error: %d", parser->state);
}
