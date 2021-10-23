
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
#include <sys/time.h>
#include <limits.h>
#include "./include/args.h"
#include "./utils/include/logger.h"
#include "./utils/include/buffer.h"
#include "./utils/include/selector.h"
#include <sys/signal.h>
#include "./utils/include/stm.h"
#include "./include/proxy.h"
#include "./utils/include/proxypop3nio.h"

struct pop3_proxy_args pop3_proxy_args;


int main(int argc, char *argv[])
{
    const char *err_msg = NULL;
    int ret = 0;
    parse_args(argc, argv, &pop3_proxy_args);

    close(0); // Add an  extra FD to server

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    IP_TYPE ip_type = IPV4;

    const int server = build_passive(ip_type);
    if (server < 0)
    {
        log(FATAL, "Unable to establish connection");
    }

    if (selector_fd_set_nio(server) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
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

    const struct fd_handler passive_handler = {
        .handle_read = proxy_create_connection,
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };

    ss = selector_register(selector, server, &passive_handler, OP_READ, NULL);

    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "registering fd";
        goto selector_finally;
    }

    while (TRUE)
    {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS)
        {
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

    if (server >= 0)
    {
        close(server);
    }
    return ret;
}



static int build_passive(IP_TYPE ip_type)
{
    int opt = TRUE;
    int client_socket;
    struct sockaddr_in address;
    struct sockaddr_in6 address_6;
    int net_flag = (ip_type == IPV4) ? AF_INET : AF_INET6;

    if ((client_socket = socket(net_flag, SOCK_STREAM, 0)) < 0) // Puede ser 0 por que cerramos el fd 0 para el proxy asi ganamos ud fd mas
    {
        log(ERROR, "Passive: Socket failed");
        return -1;
    }

    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    if (setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "Passive: set socket options failed");
    }

    if (ip_type == IPV4)
    {
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        //TODO: SOLVE ADDRESS RESOLUTION IN ARGS
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(pop3_proxy_args.pop3_proxy_port);
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
        address_6.sin6_port = htons(pop3_proxy_args.pop3_proxy_port);
        address_6.sin6_addr = in6addr_any;
        if (bind(client_socket, (struct sockaddr *)&address_6, sizeof(address_6)) < 0)
        {

            log(ERROR, "Passive: bind failed");
            close(client_socket);
            return -1;
        }
    }

    if (listen(client_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(ERROR, "Passive: listen socket failed");
        close(client_socket);
        return -1;
    }
    else
    {
        log(DEBUG, "Waiting for TCP connections on socket %d\n", client_socket);
    }
    return client_socket;
}

