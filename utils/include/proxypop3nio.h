#ifndef PROXYPOP3NIO
#define PROXYPOP3NIO

#define TRUE 1
#define FALSE 0

#include "../../utils/include/netutils.h"

typedef union address
{
    char fqdn[0xFF];
    struct sockaddr_storage addr_storage;
} address;

typedef struct address_information
{
    IP_REP_TYPE type;
    address addr;
    /** Port in network byte order */
    in_port_t port;
    socklen_t addr_length;
    int domain;

} address_information;

struct connection
{
    int fd_client;
    int fd_origin;

    struct state_machine stm;

    buffer client_buffer;
    buffer origin_buffer;

    address_information origin_address_information;
    /** Resolución de la dirección del origin server. */
    struct sockaddr_in *origin_resolution;
};

int proxy_create_connection(struct selector_key *key);
static int build_passive(IP_REP_TYPE ip_type);
#endif