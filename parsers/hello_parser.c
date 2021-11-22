#include "./include/hello_parser.h"

// Defined in RFC-1939
#define HELLO_MAX_MSG_SIZE 512

static const char *pop3_positive_responde = "+OK";
static const size_t pop3_positive_responde_size = 3;

static const char *crlf_pair = "\r\n";

void hello_parser_init(hello_parser *parser)
{
    parser->current_state = HELLO_INIT_INDICATOR;
    parser->index = 0;
}

hello_state parse_hello(hello_parser *parser, buffer *read_buffer)
{
    hello_state current_state = parser->current_state;

    while (buffer_can_read(read_buffer))
    {
        const uint8_t readed_char = buffer_read(read_buffer);
        current_state = hello_parser_input(parser, readed_char);
        if (hello_finished(current_state))
        {
            break;
        }
    }

    return current_state;
}

hello_state hello_parser_input(hello_parser *parser, uint8_t readed_char)
{
    switch (parser->current_state)
    {
    case HELLO_INIT_INDICATOR:
        if (readed_char != pop3_positive_responde[parser->index])
        {
            parser->current_state = HELLO_FAILED;
        }
        else if (parser->index == (pop3_positive_responde_size - 1))
        {
            parser->current_state = HELLO_MESSAGE;
        }
        break;

    case HELLO_MESSAGE:
        if (readed_char == crlf_pair[0])
        {
            parser->current_state = HELLO_CRLF;
        }
        break;

    case HELLO_CRLF:
        if (readed_char == crlf_pair[1])
        {
            parser->current_state = HELLO_FINISHED_CORRECTLY;
        }
        else
        {
            parser->current_state = HELLO_FAILED;
        }
        break;

    case HELLO_FINISHED_CORRECTLY:
        /* nothing to do here */

    case HELLO_FAILED:
        /* nothing to do here */
        break;

    default:
        break;
    }

    if (parser->index++ == HELLO_MAX_MSG_SIZE)
    {
        parser->current_state = HELLO_FAILED;
    }

    return parser->current_state;
}

bool hello_finished(const hello_state state)
{
    switch (state)
    {
    case HELLO_FINISHED_CORRECTLY || HELLO_FAILED:
        return true;
    default:
        return false;
    }
}