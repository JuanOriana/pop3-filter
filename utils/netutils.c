#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "./include/netutils.h"

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  struct sockaddr_storage *addr)
{
    if (addr == 0)
    {
        strncpy(buff, "null", buffsize);
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch (addr->ss_family)
    {
    case AF_INET:
        p = &((struct sockaddr_in *)addr)->sin_addr;
        port = ((struct sockaddr_in *)addr)->sin_port;
        handled = true;
        break;
    case AF_INET6:
        p = &((struct sockaddr_in6 *)addr)->sin6_addr;
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
        handled = true;
        break;
    }
    if (handled)
    {
        if (inet_ntop(addr->ss_family, p, buff, buffsize) == 0)
        {
            strncpy(buff, "unknown ip", buffsize);
            buff[buffsize - 1] = 0;
        }
    }
    else
    {
        strncpy(buff, "unknown", buffsize);
    }

    strncat(buff, ":", buffsize);
    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if (handled)
    {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }
    buff[buffsize - 1] = 0;

    return buff;
}

void get_address_representation(address_representation *address, const char *stringed_ip)
{

    memset(&(address->addr.address_storage), 0, sizeof(address->addr.address_storage));

    // Pruebo con IPv4
    address->type = ADDR_IPV4;
    address->domain = AF_INET;
    address->addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in intent_ipv4;
    memset(&(intent_ipv4), 0, sizeof(intent_ipv4));
    intent_ipv4.sin_family = AF_INET;
    int result = 0;
    if ((result = inet_pton(AF_INET, stringed_ip, &intent_ipv4.sin_addr.s_addr)) <= 0)
    {
        //Si no es v4, pruebo v6
        address->type = ADDR_IPV6;
        address->domain = AF_INET6;
        address->addr_len = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 intent_ipv6;
        memset(&(intent_ipv6), 0, sizeof(intent_ipv6));
        intent_ipv6.sin6_family = AF_INET6;
        if ((result = inet_pton(AF_INET6, stringed_ip, &intent_ipv6.sin6_addr.s6_addr)) <= 0)
        {
            // En ultima instancia DEBE ser un dominio
            memset(&(address->addr.address_storage), 0, sizeof(address->addr.address_storage));
            address->type = ADDR_DOMAIN;
            memcpy(address->addr.fqdn, stringed_ip, strlen(stringed_ip));
            return;
        }
        intent_ipv6.sin6_port = htons(address->port);
        memcpy(&address->addr.address_storage, &intent_ipv6, address->addr_len);
        return;
    }
    intent_ipv4.sin_port = htons(address->port);
    memcpy(&address->addr.address_storage, &intent_ipv4, address->addr_len);
}
