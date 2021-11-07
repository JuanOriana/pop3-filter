
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
                .type = CMD_USER, .name = "USER", .len = 4, .min_args = 1, .max_args = 512 - 7,  //un user puede contener espacios
        } , {
                .type = CMD_PASS, .name = "PASS", .len = 4, .min_args = 1, .max_args = 512 - 7,
        } , {
                .type = CMD_APOP, .name = "APOP", .len = 4, .min_args = 2, .max_args = 512 - 7,
        } , {
                .type = CMD_RETR, .name = "RETR", .len = 4, .min_args = 1, .max_args = 1,
        } , {
                .type = CMD_LIST, .name = "LIST", .len = 4, .min_args = 0, .max_args = 1,
        } , {
                .type = CMD_CAPA, .name = "CAPA", .len = 4, .min_args = 0, .max_args = 512 - 7,
        } , {
                .type = CMD_TOP,  .name = "TOP" , .len = 3, .min_args = 2, .max_args = 2,
        } , {
                .type = CMD_UIDL, .name = "UIDL", .len = 4, .min_args = 0, .max_args = 1,
        }
};


static void command_init(command_instance * command);

static command_instance * handle_command_parsed(command_instance * current_command, command_parser * parser, bool * finished, bool not_match);


void command_parser_init(command_parser * parser) {
    parser->state          = COMMAND_TYPE;
    parser->line_size       = 0;
    parser->state_size      = 0;
    parser->args_size      = 0;
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

    switch(parser->state) {
        case COMMAND_TYPE:
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
                                if(current_command->type == CMD_USER || current_command->type == CMD_APOP)
                                    current_command->data = malloc((MAX_ARG_SIZE + 1) * sizeof(uint8_t));    //NULL TERMINATED
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
            break;

        case COMMAND_ARGS:
            if(c == ' ') {
                if(parser->args_size == all_command_data[current_command->type].max_args)
                    parser->state = COMMAND_ERROR;
                else if(parser->state_size == 0)
                    parser->state_size++;
                else if(parser->state_size > 1 && parser->args_size < all_command_data[current_command->type].max_args) {
                    parser->state_size = 1;
                    parser->args_size++;
                }
            } else if(c != '\r' && c != '\n') {
                parser->crlf_state = 0;
                if(parser->state_size == 0)
                    parser->state = COMMAND_ERROR;
                else {
                    if(parser->args_size == 0 && (current_command->type == CMD_USER || current_command->type == CMD_APOP))
                        ((uint8_t *)current_command->data)[parser->state_size-1] = c;
                    parser->state_size++;
                }
            } else if(c == '\r') {
                parser->crlf_state = 1;
                if(parser->args_size == 0 && (current_command->type == CMD_USER || current_command->type == CMD_APOP))
                    ((uint8_t *)current_command->data)[parser->state_size-1] = 0;     //username null terminated
                if(parser->state_size > 1)
                    parser->args_size++;
                if(all_command_data[current_command->type].min_args <= parser->args_size && parser->args_size <= all_command_data[current_command->type].max_args) {
                    parser->state     = COMMAND_CRLF;
                } else
                    parser->state     = COMMAND_ERROR;
            } else if(c == '\n' && parser->crlf_state == 1) {
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
            break;

        case COMMAND_CRLF:
            if(c == '\r' && parser->crlf_state == 0) {
                parser->crlf_state = 1;
            } else if(c == '\n' && parser->crlf_state == 1){
                handle_command_parsed(current_command, parser, finished, false);
            }else {
                parser->state = COMMAND_ERROR;
            }
            break;

        case COMMAND_ERROR:
            if(c == '\r' && parser->crlf_state == 0) {
                parser->crlf_state = 1;
            } else if(c == '\n' && parser->crlf_state == 1 ){
                handle_command_parsed(current_command, parser, finished, true);
            }else{
                parser->crlf_state = 0;
            }
            break;
        default:
            log(ERROR,"Command parser not reconize state: %d", parser->state);
    }
    if(parser->line_size++ == MAX_MSG_SIZE || (parser->state == COMMAND_ARGS && parser->state_size == MAX_ARG_SIZE))
        parser->state = COMMAND_ERROR;
    return parser->state;
}

command_state command_parser_consume(command_parser * parser, buffer* buffer, bool pipelining, bool * finished) {
    command_state state = parser->state;

    while(buffer_can_read(buffer)) {
        const uint8_t c = buffer_read(buffer);
        state = command_parser_feed(parser, c, finished);
        if(!pipelining && *finished) {
            break;
        }
    }
    return state;
}

char * get_user(const command_instance command) {
    if(command.type == CMD_APOP || command.type == CMD_USER)
        return (char * ) command.data;
    return NULL;
}

void command_delete(command_instance * command) {
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

static command_instance * handle_command_parsed(command_instance * current_command, command_parser * parser, bool * finished, bool not_match) {
    command_instance * new_command = malloc(sizeof(command_instance));

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

    return new_command;
}
