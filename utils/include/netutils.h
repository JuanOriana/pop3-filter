#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <netinet/in.h>

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)
#define N_BUFFER(x) (sizeof(x) / sizeof((x)[0]))

typedef enum IP_REP_TYPE
{
    ADDR_IPV4,
    ADDR_IPV6,
    ADDR_DOMAIN,
} IP_REP_TYPE;

typedef union address_multi_storage
{
    char fqdn[0xFF];
    struct sockaddr_storage address_storage;
} address_multi_storage;

/**
 * Representacion general de cualquier itpo de address.
 */
typedef struct address_representation
{
    IP_REP_TYPE type;
    address_multi_storage addr;
    /** Port in network byte order */
    in_port_t port;
    socklen_t addr_len;
    int domain;
} address_representation;

/**
 * Parsea un string a la representasion address correspondiente (IPv4,IPV6 o dominio).
 */
void get_address_representation(address_representation *address, const char *stringed_ip);

/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 * @param af    address family
 * @param addr  la dirección en si
 * @param nport puerto en network byte order
 *
 */
const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr);
#endif
