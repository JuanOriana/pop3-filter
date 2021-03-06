#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include "stdint.h"

#define TRUE 1
#define FALSE 0

#define DEFAULT_ERROR_FILE "/dev/null"
#define DEFAULT_ORIGIN_PORT 110
#define DEFAULT_PROXY_ADDR "0.0.0.0"
#define DEFAULT_PROXY_PORT 1110
#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_PORT 9090
#define DEFAULT_BUFF_SIZE 2048
#define DEFAULT_TIMEOUT 200
#define DEFAULT_PROXY_POP3_VERSION_NUMBER "1.0"


struct pop3_proxy_state
{
    uint32_t            historic_connections;
    uint32_t            current_connections;
    uint32_t            bytes_transfered;
    uint16_t            buff_size;
    uint8_t             timeout;
    char *              pop3_proxy_addr;
    unsigned short      pop3_proxy_port;
    char *              origin_addr;
    bool                proxy_on_both;
    unsigned short      origin_port;
    char *              mng_addr;
    bool                mng_on_both;
    unsigned short      mng_port;
    char                filter[1024];
    bool                filter_activated;
    char                error_file[1024];
    char *              version_number;
    uint32_t            auth_tk;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void parse_args(const int argc, char **argv, struct pop3_proxy_state *args);

#endif
