
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "./include/command_parser.h"
#include "../utils/include/logger.h"

typedef struct command_data {
    command_t type;
    char *    name;
    int       len;
    int       min_args;
    int       max_args;
} command_data;

#define IS_MULTILINE(command, args_size) (command->type == CMD_CAPA       \
                ||  (command->type == CMD_LIST && args_size == 0)         \
                ||  (command->type == CMD_TOP  && args_size == 2)         \
                ||  (command->type == CMD_RETR && args_size == 1)         \
                ||  (command->type == CMD_UIDL && args_size == 0))

static const command_data all_command_data[] = {
        {
                .type = CMD_USER, .name = "USER", .len = 4, .min_args = 1, .max_args = MAX_MSG_SIZE - 4 - 2 - 1,  // largo comando + crlf + espacio incial
        } , {
                .type = CMD_PASS, .name = "PASS", .len = 4, .min_args = 1, .max_args = MAX_MSG_SIZE - 4 - 2 - 1,
        } , {
                .type = CMD_APOP, .name = "APOP", .len = 4, .min_args = 2, .max_args = MAX_MSG_SIZE - 4 - 2 - 1,
        } , {
                .type = CMD_RETR, .name = "RETR", .len = 4, .min_args = 1, .max_args = 1,
        } , {
                .type = CMD_LIST, .name = "LIST", .len = 4, .min_args = 0, .max_args = 1,
        } , {
                .type = CMD_CAPA, .name = "CAPA", .len = 4, .min_args = 0, .max_args = MAX_MSG_SIZE - 4 - 2 - 1,
        } , {
                .type = CMD_TOP,  .name = "TOP" , .len = 3, .min_args = 2, .max_args = 2,
        } , {
                .type = CMD_UIDL, .name = "UIDL", .len = 4, .min_args = 0, .max_args = 1,
        }, {
                .type = CMD_QUIT, .name = "QUIT", .len = 4, .min_args = 0, .max_args = 0,
        }, {
                .type = CMD_DELE, .name = "DELE", .len = 4, .min_args = 1, .max_args = 1,
        }, {
                .type = CMD_NOOP, .name = "NOOP", .len = 4, .min_args = 0, .max_args = 0,
        }, {
                .type = CMD_STAT, .name = "STAT", .len = 4, .min_args = 0, .max_args = 0,
        }
};

typedef void (*command_handler_f) ( command_parser *, char, bool *, command_instance *);

static void command_type_state (command_parser * parser, char c, bool * finished, command_instance * current_command);
static void command_args_state (command_parser * parser, char c, bool * finished, command_instance * current_command);
static void command_crlf_state (command_parser * parser, char c, bool * finished, command_instance * current_command);
static void command_error_state (command_parser * parser, char c, bool * finished, command_instance * current_command);

command_handler_f command_handlers[] = {command_type_state,command_args_state,command_crlf_state,command_error_state};

static void command_init(command_instance * command);
static void handle_command_parsed(command_instance * current_command, command_parser * parser, bool * finished, bool not_match);

void command_parser_init(command_parser * parser) {
    parser->state          = COMMAND_TYPE;
    parser->line_size       = 0;
    parser->state_size      = 0;
    parser->args_size      = 0;
    parser->is_expecting_new_arg = false;
}

command_state command_parser_feed(command_parser * parser, const char c, bool * finished) {
    command_instance * current_command = &parser->current_command;

    if(parser->line_size == 0) {
        command_init(current_command);
        parser->crlf_state   = 0;
        parser->args_size    = 0;
        parser->invalid_size = 0;
        for(int i = 0; i < SIZE_OF_CMD_TYPES; i++)
            parser->invalid_type[i] = false;
    }

    if (parser->state > COMMAND_ERROR){
        log(ERROR,"Command parser not reconize state: %d", parser->state);
    }
    else{
        command_handlers[parser->state](parser, c, finished, current_command);
    }

    if(parser->line_size++ == MAX_MSG_SIZE || (parser->state == COMMAND_ARGS && parser->state_size == MAX_ARG_SIZE))
        parser->state = COMMAND_ERROR;
    return parser->state;
}

command_state command_parser_consume(command_parser * parser, buffer* buffer, bool pipelining, bool * finished, size_t * n_consumed) {
    command_state state = parser->state;
    size_t n = 0;
    while(buffer_can_read(buffer)) {
        n++;
        const uint8_t c = buffer_read(buffer);
        state = command_parser_feed(parser, c, finished);
        if(!pipelining && *finished) {
            break;
        }
    }
    *n_consumed = n;
    return state;
}

char * get_user(const command_instance command) {
    if(command.type == CMD_APOP || command.type == CMD_USER)
        return (char * ) command.data;
    return NULL;
}

void  command_delete(command_instance * command) {
    if(command == NULL)
        return;
    if(command->data != NULL)
        free(command->data);
    free(command);
}

static void command_init(command_instance * command) {
    command->type = CMD_NOT_RECOGNIZED;
    command->indicator = false;
    command->data = NULL;
}

static void handle_command_parsed(command_instance * current_command, command_parser * parser, bool * finished, bool not_match) {

    if(not_match) {
        current_command->type = CMD_NOT_RECOGNIZED;
        if(current_command->data != NULL) {
            free(current_command->data);
            current_command->data = NULL;
        }
    }

    current_command->is_multi = IS_MULTILINE(current_command, parser->args_size);

    parser->state     = COMMAND_TYPE;
    parser->line_size  = -1;
    parser->state_size =  0;
    *finished = true;

}

// modules for command_parser_feed's switch
static void command_type_state (command_parser * parser, const char c, bool * finished, command_instance * current_command) {
    if(c != '\n') {
        for(int i = 0; i < SIZE_OF_CMD_TYPES; i++) {
            if(!parser->invalid_type[i]) {
                if(toupper(c) != all_command_data[i].name[parser->line_size]) {
                    parser->invalid_type[i] = true;
                    parser->invalid_size++;
                } else if(parser->line_size == all_command_data[i].len-1) {
                    current_command->type = all_command_data[i].type;
                    parser->state_size = 0;
                    if(all_command_data[i].max_args > 0) {
                        if(current_command->type == CMD_USER || current_command->type == CMD_APOP) {
                            if (current_command->data == NULL) {
                                current_command->data = calloc(MAX_ARG_SIZE + 1,sizeof(uint8_t));    //NULL TERMINATED
                            }
                            else{
                                memset(current_command->data,0,MAX_ARG_SIZE + 1);
                            }
                        }
                        parser->state = COMMAND_ARGS;
                    } else
                        parser->state = COMMAND_CRLF;
                    break;
                }
            }
            if(parser->invalid_size == SIZE_OF_CMD_TYPES)
                parser->state = COMMAND_ERROR;
        }
    } else
        handle_command_parsed(current_command, parser, finished, true);
}

static void command_args_state (command_parser * parser, const char c, bool * finished, command_instance * current_command) {

    // Espacio indica nuevo argumento
    if(c == ' ') {
        parser->is_expecting_new_arg = true;
    }
    // Leyendo un argumento
    else if(c != '\r' && c != '\n') {
        if (parser->is_expecting_new_arg){
            if(parser->args_size == all_command_data[current_command->type].max_args)
                parser->state = COMMAND_ERROR;
            else if(parser->state_size == 0)
                parser->state_size++;
            else if(parser->state_size > 1 && parser->args_size < all_command_data[current_command->type].max_args) {
                parser->state_size = 1;
                parser->args_size++;
            }
            parser->is_expecting_new_arg = false;
        }
        parser->crlf_state = 0;
        if(parser->state_size == 0)
            parser->state = COMMAND_ERROR;
        else {
            if(parser->args_size == 0 && (current_command->type == CMD_USER || current_command->type == CMD_APOP))
                ((uint8_t *)current_command->data)[parser->state_size-1] = c;
            parser->state_size++;
        }
    }
    else if(c == '\r') {
        parser->crlf_state = 1;
        if(parser->args_size == 0 && (current_command->type == CMD_USER || current_command->type == CMD_APOP))
            ((uint8_t *)current_command->data)[parser->state_size > 0 ? parser->state_size-1: 0] = 0;     //username null terminated
        if(parser->state_size > 1)
            parser->args_size++;
        if(all_command_data[current_command->type].min_args <= parser->args_size && parser->args_size <= all_command_data[current_command->type].max_args) {
            parser->state     = COMMAND_CRLF;
        } else
            parser->state     = COMMAND_ERROR;
    }
    // Es imposible que c != '\n' si llegamos aca, es un tema de claridad
    else if(c == '\n' && parser->crlf_state == 1) {
        parser->crlf_state = 2;
        if(parser->args_size == 0 && (current_command->type == CMD_USER || current_command->type == CMD_APOP))
            ((uint8_t *)current_command->data)[parser->state_size-1] = 0;     //username null terminated
        if(parser->state_size > 1)
            parser->args_size++;
        if(all_command_data[current_command->type].min_args <= parser->args_size && parser->args_size <= all_command_data[current_command->type].max_args) {
            handle_command_parsed(current_command, parser, finished, false);
        } else
            handle_command_parsed(current_command, parser, finished, true);
    } else {
        parser->crlf_state = 0;
        parser->state = COMMAND_ERROR;
    }
}

static void command_crlf_state (command_parser * parser, const char c, bool * finished, command_instance * current_command) {
    if(c == '\r' && parser->crlf_state == 0) {
        parser->crlf_state = 1;
    } else if(c == '\n' && parser->crlf_state == 1){
        handle_command_parsed(current_command, parser, finished, false);
    }else {
        parser->state = COMMAND_ERROR;
    }
}

static void command_error_state (command_parser * parser, const char c, bool * finished, command_instance * current_command) {
    if(c == '\r' && parser->crlf_state == 0) {
        parser->crlf_state = 1;
    } else if(c == '\n'){
        handle_command_parsed(current_command, parser, finished, true);
    }else{
        parser->crlf_state = 0;
    }
}