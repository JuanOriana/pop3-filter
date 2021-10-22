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
#include "./utils/include/logger.h"
#include "./include/proxy.h"
#include "./utils/include/selector.h"
#include "./utils/include/buffer.h"
#include <sys/signal.h>

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))

#define TRUE 1
#define FALSE 0
#define DEFAULT_SERVER_PORT 8888
#define DEFAULT_ORIGIN_PORT 110
#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define MAX_PENDING_CONNECTIONS 3 // un valor bajo, para realizar pruebas

typedef enum
{
    IPV4,
    IPV6
} IP_TYPE;

typedef enum
{
    RESOLVING,
    CONNECTING,
    COPYING,
    DONE,
} proxy_state;

typedef struct state_definition state_definition;
struct state_definition
{
    proxy_state state;
    const fd_handler handler;
};

struct connection
{
    int fd_client;
    int fd_origin;
    state_definition *state_definition;
    buffer client_buffer;
    buffer origin_buffer;
};

struct state_definition client_states[] = {
    {
        .state = RESOLVING,
        .handler.handle_read = NULL,
        .handler.handle_write = NULL,
        .handler.handle_close = NULL,
    },
    {
        .state = CONNECTING,
        .handler.handle_read = NULL,
        .handler.handle_write = NULL,
        .handler.handle_close = NULL,
    },
    {
        .state = COPYING,
        .handler.handle_read = NULL,
        .handler.handle_write = NULL,
        .handler.handle_close = NULL,
    }};

int build_passive(IP_TYPE ip_type);

int main(int argc, char *argv[])
{
    unsigned port = DEFAULT_SERVER_PORT;
    // if(argc == 2) {
    //     // utilizamos el default
    // } else if(argc == 3) {
    //     char *end     = 0;
    //     const long sl = strtol(argv[1], &end, 10);

    //     if (end == argv[2]|| '\0' != *end
    //        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
    //        || sl < 0 || sl > USHRT_MAX) {
    //         logger(FATAL, "port should be an integer: %s\n", argv[1]);
    //     }
    //     port = sl;
    // } else {
    //     logger(FATAL, "Usage: %s <addr> <port>\n", argv[0]);
    // }

    close(0); // Add an  extra FD to server

    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;
    IP_TYPE ip_type = IPV4;

    const int server = build_passive(ip_type);
    if (server < 0)
    {
        logger(FATAL, "Unable to establish connection");
    }

    if (selector_fd_set_nio(server) == -1)
    {
        err_msg = "getting server socket flags";
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

    selector = selector_new(1024);

    if (selector == NULL)
    {
        err_msg = "unable to create selector";
        goto selector_finally;
    }

    const struct fd_handler passive_handler = {
        .handle_read = proxy_create_connection, // TODO: crear conexion activa y subscribirla al selector
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

    int ret = 0;

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

    socksv5_pool_destroy();

    if (server >= 0)
    {
        close(server);
    }
    return ret;
}

int build_passive(IP_TYPE ip_type)
{
    int opt = TRUE;
    int client_socket;
    struct sockaddr_in address;
    struct sockaddr_in6 address_6;
    int net_flag = (ip_type == IPV4) ? AF_INET : AF_INET6;

    if ((client_socket = socket(net_flag, SOCK_STREAM, 0)) == 0)
    {
        log(ERROR, "socket failed");
        return -1;
    }

    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    if (setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "set socket options failed");
    }

    if (ip_type == AF_INET)
    {
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(DEFAULT_SERVER_PORT);
        if (bind(client_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            log(ERROR, "bind failed");
            close(client_socket);
            return -1;
        }
    }
    else
    {
        memset(&address_6, 0, sizeof(address_6));
        address_6.sin6_family = AF_INET6;
        address_6.sin6_port = htons(DEFAULT_SERVER_PORT);
        address_6.sin6_addr = in6addr_any;
        if (bind(client_socket, (struct sockaddr *)&address_6, sizeof(address_6)) < 0)
        {
            log(ERROR, "bind failed");
            close(client_socket);
            return -1;
        }
    }

    if (listen(client_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(ERROR, "listen socket failed");
        close(client_socket);
        return -1;
    }
    else
    {
        log(DEBUG, "Waiting for TCP connections on socket %d\n", client_socket);
    }
    return client_socket;
}

int proxy_create_connection(struct selector_key *key)
{
    struct sockaddr_storage client_address; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t client_address_len = sizeof(client_address);

    // Wait for a client to connect
    int client_socket = accept(key->fd, (struct sockaddr *)&client_address, &client_address_len);
    if (client_socket < 0)
    {
        log(ERROR, "accept() failed");
        return -1;
    }

    // client_socket is connected to a client!
    log(INFO, "Handling client %s", addrBuffer);

    // TODO: CREAR HANDLER
    ss = selector_register(key->s, client_socket, NULL, NULL, NULL); // Third parameter is null since non-handling is needed

    return client_socket;
}