
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <limits.h>
#include "./include/args.h"
#include "./utils/include/logger.h"
#include "./utils/include/buffer.h"
#include "./utils/include/selector.h"
#include "./utils/include/netutils.h"
#include "./manager/include/manager_server.h"

#include <sys/signal.h>
#include "./utils/include/stm.h"
#include "./include/main.h"
#include "proxy/include/proxypop3nio.h"

struct pop3_proxy_args pop3_proxy_args;

#define MAX_PENDING_CONNECTIONS 20
#define SELECTOR_SIZE 1024

static int build_passive(IP_REP_TYPE ip_type,passive_type passive_type);

static bool done = false;

int main(int argc, char *argv[])
{
    const char *err_msg = NULL;
    int ret = 0;
    int proxy4 = -1, proxy6 = -1, manag4=-1, manag6=-1;
    address_representation origin_representation;
    parse_args(argc, argv, &pop3_proxy_args);

    close(0); // Add an  extra FD to server

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    proxy4 = build_passive(ADDR_IPV4, PASSIVE_TCP);
    if (proxy4 < 0)
    {
        log(DEBUG, "Unable to build passive socket in IPv4");
    }
    else if (selector_fd_set_nio(proxy4) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }

    proxy6 = build_passive(ADDR_IPV6, PASSIVE_TCP);

    if (proxy6 < 0)
    {
        log(DEBUG, "Unable to build passive socket in IPv6");
    }
    else if (selector_fd_set_nio(proxy6) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }

    if (proxy4 < 0 && proxy6 < 0)
    {
        log(FATAL, "Couldnt establish ANY passive socket for proxy");
    }

    manag4 = build_passive(ADDR_IPV4, PASSIVE_UDP);

    if (manag4 < 0)
    {
        log(DEBUG, "Unable to build manager passive socket in IPv4");
    }
    else if (selector_fd_set_nio(manag4) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }

    manag6 = build_passive(ADDR_IPV6, PASSIVE_UDP);

    if (manag6 < 0)
    {
        log(DEBUG, "Unable to build manager passive socket in IPv6");
    }
    else if (selector_fd_set_nio(manag6) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }

    if (manag4 < 0 && manag6 < 0)
    {
        log(FATAL, "Couldnt establish ANY passive socket for manager");
    }

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0,
        },
    };
    if (0 != selector_init(&conf))
    {
        err_msg = "initializing selector";
        goto selector_finally;
    }

    selector = selector_new(SELECTOR_SIZE);

    if (selector == NULL)
    {
        err_msg = "unable to create selector";
        goto selector_finally;
    }

    const struct fd_handler proxy_passive_handler = {
        .handle_read = proxy_passive_accept,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    const struct fd_handler manager_passive_handler = {
            .handle_read = manager_passive_accept,
            .handle_write = NULL,
            .handle_close = NULL, // nada que liberar
    };

    // Mando una representacion del origen al selector para generar los sockets activos
    origin_representation.port = pop3_proxy_args.origin_port;
    get_address_representation(&origin_representation, pop3_proxy_args.origin_addr);

    if (proxy4 >= 0)
    {
        ss = selector_register(selector, proxy4, &proxy_passive_handler, OP_READ, &origin_representation);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv4 passive fd";
            goto selector_finally;
        }
    }

    if (proxy6 >= 0)
    {
        ss = selector_register(selector, proxy6, &proxy_passive_handler, OP_READ, &origin_representation);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv6 passive fd";
            goto selector_finally;
        }
    }

    if (manag4 >= 0)
    {
        ss = selector_register(selector, manag4, &manager_passive_handler, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv4 manager passive fd";
            goto selector_finally;
        }
    }

    if (manag6 >= 0)
    {
        ss = selector_register(selector, manag6, &manager_passive_handler, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering ipv6 manager passive fd";
            goto selector_finally;
        }
    }

    time_t last_used = time(NULL);
    time_t current_time = time(NULL);

    for (;!done;)
    {
        err_msg = NULL;
        ss = selector_select(selector);
        current_time = time(NULL);
        if(difftime(current_time,last_used)>=TIMEOUT){
        // log(DEBUG,"DIFFTIME = %f AND current = %ld and last %ld ",difftime(current_time,last_used),current_time,last_used);
            last_used = current_time;
            selector_check_time_out(selector);
        }
            if (ss != SELECTOR_SUCCESS)
        {
            log(ERROR,"%s",selector_error(ss));
            err_msg = "serving";
            goto selector_finally;
        }
    }
    if (err_msg == NULL)
    {
        err_msg = "closing";
    }

selector_finally:
    if (ss != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                    ? strerror(errno)
                    : selector_error(ss));
        ret = 2;
    }
    else if (err_msg)
    {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL)
    {
        selector_destroy(selector);
    }
    selector_close();

    if (proxy4 >= 0)
    {
        close(proxy4);
    }
    if (proxy6 >= 0)
    {
        close(proxy6);
    }
    if (manag4 >= 0)
    {
        close(proxy6);
    }
    if (manag6 >= 0)
    {
        close(proxy6);
    }
    connection_pool_destroy();
    return ret;
}

static int build_passive(IP_REP_TYPE ip_type, passive_type passive_type)
{
    int opt = TRUE, result = -1;
    int client_socket;
    struct sockaddr_in address;
    struct sockaddr_in6 address_6;
    int net_flag = (ip_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int sock_type = passive_type == PASSIVE_UDP ? SOCK_DGRAM : SOCK_STREAM;
    int port = passive_type == PASSIVE_TCP ? pop3_proxy_args.pop3_proxy_port : pop3_proxy_args.mng_port;
    char * stringed_addr = passive_type == PASSIVE_TCP ? pop3_proxy_args.pop3_proxy_addr : pop3_proxy_args.mng_addr;

    if ((client_socket = socket(net_flag, sock_type, 0)) < 0) // Puede ser 0 por que cerramos el fd 0 para el proxy asi ganamos ud fd mas
    {
        log(ERROR, "Passive: Socket failed");
        return -1;
    }

    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    if (passive_type == PASSIVE_TCP && setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "Passive: set socket options failed");
    }

    if (ip_type == ADDR_IPV4)
    {
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        if ((result = inet_pton(AF_INET, stringed_addr, &address.sin_addr.s_addr)) <= 0)
        {
            log(ERROR, "Cant resolve IPv4 stringed address");
            close(client_socket);
            return -1;
        }
        address.sin_port =  htons(port);
        if (bind(client_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            log(ERROR, "Passive: bind failed");
            close(client_socket);
            return -1;
        }
    }
    else
    {
        memset(&address_6, 0, sizeof(address_6));
        address_6.sin6_family = AF_INET6;
        address_6.sin6_port = htons(port);
        if ((result = inet_pton(AF_INET6, stringed_addr, &address_6.sin6_addr)) <= 0)
        {
            log(ERROR, "Cant resolve IPv6 stringed address");
            close(client_socket);
            return -1;
        }
        if (bind(client_socket, (struct sockaddr *)&address_6, sizeof(address_6)) < 0)
        {

            log(ERROR, "Passive: bind failed");
            close(client_socket);
            return -1;
        }
    }

    if (passive_type == PASSIVE_TCP && listen(client_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(ERROR, "Passive: listen socket failed");
        close(client_socket);
        return -1;
    }
    else
    {
        log(INFO, "Waiting for %s TCP connections on socket %d\n",ip_type == ADDR_IPV4?"IPv4":"IPV6", client_socket);
    }
    return client_socket;
}

