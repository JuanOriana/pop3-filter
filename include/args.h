#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

struct pop3_proxy_args
{
    char *pop3_proxy_addr;
    unsigned short pop3_proxy_port;
    char *origin_addr;
    unsigned short origin_port;
    char *mng_addr;
    unsigned short mng_port;
    char *filter;
    char *error_file;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void parse_args(const int argc, char **argv, struct pop3_proxy_args *args);

#endif