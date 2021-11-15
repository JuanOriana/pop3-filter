
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

extern struct pop3_proxy_args pop3_proxy_args;

#define MAX_PENDING_CONNECTIONS 20
#define SELECTOR_SIZE 1024

static int build_passive(IP_REP_TYPE ip_type,passive_type passive_type);

static bool done = false;

int main(int argc, char *argv[])
{
    const char *err_msg = NULL;
    int ret = 0;
    int temp_sock=-1;
    int proxy_socks[2],proxy_socks_size =0, manag_socks[2], manag_socks_size = 0;
    address_representation origin_representation;
    parse_args(argc, argv, &pop3_proxy_args);

    close(0); // Add an  extra FD to server

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    temp_sock = build_passive(ADDR_IPV4, PASSIVE_TCP);
    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build proxy passive socket in IPv4");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }
    else{
        proxy_socks[proxy_socks_size++] = temp_sock;
    }

    temp_sock = build_passive(ADDR_IPV6, PASSIVE_TCP);

    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build proxy passive socket in IPv6");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }
    else{
        proxy_socks[proxy_socks_size++] = temp_sock;
    }

    if (proxy_socks_size == 0)
    {
        log(FATAL, "Couldnt establish ANY passive socket for proxy");
    }

    temp_sock = build_passive(ADDR_IPV4, PASSIVE_UDP);

    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build manager passive socket in IPv4");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }
    else{
        manag_socks[manag_socks_size++] = temp_sock;
    }

    temp_sock = build_passive(ADDR_IPV6, PASSIVE_UDP);

    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build manager passive socket in IPv6");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("SELECTOR ");
        err_msg = "Proxy: Selector_fd_set_nio, getting server socket flags";
        goto selector_finally;
    }
    else{
        manag_socks[manag_socks_size++] = temp_sock;
    }

    if (manag_socks_size == 0)
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

    for (int i = 0; i < proxy_socks_size; i++){
        ss = selector_register(selector, proxy_socks[i], &proxy_passive_handler, OP_READ, &origin_representation);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering proxy passive fd";
            goto selector_finally;
        }
    }

    for (int i = 0; i < manag_socks_size; i++){
        ss = selector_register(selector, manag_socks[i], &manager_passive_handler, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS)
        {
            err_msg = "registering manager passive fd";
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
        if(difftime(current_time,last_used)>=pop3_proxy_args.timeout){
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

    for (int i = 0; i < proxy_socks_size; i++){
        close(proxy_socks[i]);
    }

    for (int i = 0; i < manag_socks_size; i++){
        close(manag_socks[i]);
    }

    connection_pool_destroy();
    return ret;
}

static int build_passive(IP_REP_TYPE ip_type, passive_type passive_type)
{
    int opt = TRUE;
    int client_socket;
    struct sockaddr_in address;
    struct sockaddr_in6 address_6;
    int net_flag = (ip_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int sock_type = passive_type == PASSIVE_UDP ? SOCK_DGRAM : SOCK_STREAM;
    int port = passive_type == PASSIVE_TCP ? pop3_proxy_args.pop3_proxy_port : pop3_proxy_args.mng_port;
    char * stringed_addr = passive_type == PASSIVE_TCP ? pop3_proxy_args.pop3_proxy_addr : pop3_proxy_args.mng_addr;

    // Si estamos escuchando en TODAS las interfaces, hacemos que se cumpla tambien en IPv6
    // TODO: preguntar
    if (strcmp(stringed_addr,"0.0.0.0") == 0 && ip_type == ADDR_IPV6 ){
        stringed_addr = "0::0";
    }

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
        if (inet_pton(AF_INET, stringed_addr, &address.sin_addr.s_addr) <= 0)
        {
            log(DEBUG, "String address doesn't translate to IPv4");
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
        if (inet_pton(AF_INET6, stringed_addr, &address_6.sin6_addr) <= 0)
        {
            log(DEBUG, "String address doesn't translate to IPv6");
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
        log(INFO, "Waiting for %s %s connections on socket %d",ip_type == ADDR_IPV4?"IPv4":"IPV6", passive_type == PASSIVE_TCP?"proxy":"manager", client_socket);
    }
    return client_socket;
}

