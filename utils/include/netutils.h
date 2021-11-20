#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <netinet/in.h>

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)
#define N_BUFFER(x) (sizeof(x) / sizeof((x)[0]))

typedef enum ip_rep_type
{
    ADDR_IPV4,
    ADDR_IPV6,
    ADDR_DOMAIN,
} ip_rep_type;

typedef enum passive_type
{
    PASSIVE_TCP,
    PASSIVE_UDP,
} passive_type;

typedef union address_multi_storage
{
    char fqdn[0xFF];
    struct sockaddr_storage address_storage;
} address_multi_storage;

/**
 * Representacion general de cualquier tipo de address, ya sea ipv4; ivp6 o un dominio
 * el puerto debe ser precargado antes de usar get_address_representation
 */
typedef struct address_representation
{
    ip_rep_type type;
    address_multi_storage addr;
    in_port_t port;
    socklen_t addr_len;
    int domain;
} address_representation;

/**
 * Parsea un string a la address_representation correspondiente (IPv4, IPV6 o dominio).
 *
 * @param address     la representacion donde quedara guardada
 * @param stringed_ip la ip en formato string
 *
 */
void get_address_representation(address_representation *address, const char *stringed_ip);

/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 */
const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  struct sockaddr_storage *addr);
#endif
