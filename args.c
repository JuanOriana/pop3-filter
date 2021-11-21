#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <limits.h> /* LONG_MIN et al */
#include <string.h> /* memset */
#include <errno.h>
#include <getopt.h>
#include "./include/args.h"

struct pop3_proxy_state pop3_proxy_state;


static unsigned short
port(const char *s)
{
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "Port should in in the range of 1-65536: %s\n", s);
        exit(EXIT_FAILURE);
    }
    return (unsigned short)sl;
}

static void
version(void)
{
    fprintf(stderr, "Pop3Filter version " DEFAULT_PROXY_POP3_VERSION_NUMBER "\n"
                    "ITBA Protocolos de Comunicación 2021/2 -- Grupo 6\n"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [OPTION] origin-server\n"
            "\n"
            "Arguments:\n"
            "   -origin-server   Dirección del servidor origen POP3.\n"
            "Options:\n"
            "\n"
            "   -e <error file>  Archivo donde se redirecciona el stderr.\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <pop3 addr>   Dirección donde serviría el proxy POP3.\n"
            "   -L <conf  addr>  Dirección donde serviría el servicio de management.\n"
            "   -o <conf port>   Puerto entrante conexiones management\n"
            "   -p <pop3 port>   Puerto entrante conexiones POP3.\n"
            "   -P <origin port> Puerto del servidor POP3 en el servidor origen\n"
            "   -t <cmd>         Comando utilizado para las transformaciones externas.  Compatible con system(3).\n"
            "   -v               Imprime información sobre la versión y termina.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char **argv, struct pop3_proxy_state *args)
{
    memset(args, 0, sizeof(*args));

    args->buff_size = DEFAULT_BUFF_SIZE;
    args->timeout = DEFAULT_TIMEOUT;
    memcpy(args->error_file,DEFAULT_ERROR_FILE,strlen(DEFAULT_ERROR_FILE));
    args->pop3_proxy_addr = DEFAULT_PROXY_ADDR;
    args->proxy_on_both = true;
    args->pop3_proxy_port = DEFAULT_PROXY_PORT;
    args->mng_addr = DEFAULT_MNG_ADDR;
    args->mng_on_both = true;
    args->mng_port = DEFAULT_MNG_PORT;
    args->origin_port = DEFAULT_ORIGIN_PORT;
    args->historic_connections = 0;
    args->current_connections = 0;
    args->bytes_transfered = 0;
    args->version_number = DEFAULT_PROXY_POP3_VERSION_NUMBER;
    args->filter_activated = FALSE;

    int c;

    while (true)
    {

        c = getopt(argc, argv, "e:hl:L:o:p:P:t:v");
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'e':
            memcpy(args->error_file,optarg,strlen(optarg));
            break;
        case 'l':
            args->pop3_proxy_addr = optarg;
            args->proxy_on_both = false;
            break;
        case 'L':
            args->mng_addr = optarg;
            args->mng_on_both = false;
            break;
        case 'p':
            args->pop3_proxy_port = port(optarg);
            break;
        case 'P':
            args->origin_port = port(optarg);
            break;
        case 'o':
            args->mng_port = port(optarg);
            break;
        case 't':
            //TODO: CHECK IF FILTER IS VALID
            args->filter_activated = TRUE;
            memcpy(args->filter,optarg,strlen(optarg));
            break;
        case 'v':
            version();
            exit(0);
            break;
        default:
            fprintf(stderr, "Unknown argument %d.\n", c);
            exit(EXIT_FAILURE);
        }
    }
    if (optind < argc - 1)
    {
        fprintf(stderr, "Argument not accepted: ");
        while (optind < argc - 1)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }
    if (optind >= argc)
    {
        fprintf(stderr, "Expected argument after options\n");
        exit(EXIT_FAILURE);
    }
    args->origin_addr = argv[optind];
}