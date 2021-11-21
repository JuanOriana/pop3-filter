
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "./include/args.h"
#include "./utils/include/logger.h"
#include "./utils/include/selector.h"
#include "./utils/include/netutils.h"
#include "./manager/include/manager_server.h"
#include <sys/signal.h>
#include "proxy/include/proxypop3nio.h"

#define MAX_PENDING_CONNECTIONS 20
#define SELECTOR_SIZE 1024

extern struct pop3_proxy_state pop3_proxy_state;

/*
 * Construye un socket generico dado un tipo de ip (v4 o v6) y un tipo de socket pasivo
 *  (Manager -> UDP o proxy -> TCP)
 */
static int build_passive(ip_rep_type ip_type,passive_type passive_type);

static bool done = false;

int main(int argc, char *argv[])
{
    const char *err_msg = NULL;
    int ret = 0;
    int temp_sock=-1;
    int proxy_socks[2],proxy_socks_size =0, manag_socks[2], manag_socks_size = 0;
    address_representation origin_representation;
    parse_args(argc, argv, &pop3_proxy_state);

    close(0); // Tengo un fd mas para el server

    selector_status ss = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    // Pruebo con los pasivos del proxy
    temp_sock = build_passive(ADDR_IPV4, PASSIVE_TCP);
    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build proxy passive socket in IPv4");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("selector_fd_set_nio");
        err_msg = "Proxy: selector_fd_set_nio, getting proxy ipv4 as non blocking";
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
        perror("selector_fd_set_nio");
        err_msg = "Proxy: selector_fd_set_nio, getting proxy ipv6 as non blocking";
        goto selector_finally;
    }
    else{
        proxy_socks[proxy_socks_size++] = temp_sock;
    }

    // Si no pude levantar ningun proxy, no puedo avanzar
    if (proxy_socks_size == 0)
    {
        log(FATAL, "Couldnt establish ANY passive socket for proxy");
    }

    // Hago lo mismo para el manager

    temp_sock = build_passive(ADDR_IPV4, PASSIVE_UDP);

    if (temp_sock < 0)
    {
        log(DEBUG, "Unable to build manager passive socket in IPv4");
    }
    else if (selector_fd_set_nio(temp_sock) == -1)
    {
        perror("selector_fd_set_nio");
        err_msg = "Proxy: selector_fd_set_nio, getting manager ipv4 as non blocking";
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
        perror("selector_fd_set_nio");
        err_msg = "Proxy: selector_fd_set_nio, getting manager ipv6 as non blocking";
        goto selector_finally;
    }
    else{
        manag_socks[manag_socks_size++] = temp_sock;
    }

    // Idem caso proxy (Tecnicamente podria continuar la ejecucion sin managers levantados si asi lo quisiese
    // pero es una decision del grupo)

    if (manag_socks_size == 0)
    {
        log(FATAL, "Couldnt establish ANY passive socket for manager");
    }

    // Timeout setting

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
        .handle_close = NULL,
    };

    const struct fd_handler manager_passive_handler = {
            .handle_read = manager_passive_accept,
            .handle_write = NULL,
            .handle_close = NULL,
    };

    // Mando una representacion del origen al selector para generar los sockets activos
    origin_representation.port = pop3_proxy_state.origin_port;
    get_address_representation(&origin_representation, pop3_proxy_state.origin_addr);

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
    time_t current_time;

    for (;!done;)
    {
        err_msg = NULL;
        ss = selector_select(selector);
        current_time = time(NULL);
        if(difftime(current_time,last_used) >= pop3_proxy_state.timeout){
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

static int build_passive(ip_rep_type ip_type, passive_type passive_type)
{
    int opt = TRUE;
    int new_socket;
    struct sockaddr_in address;
    struct sockaddr_in6 address_6;
    int net_flag = (ip_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int sock_type = passive_type == PASSIVE_UDP ? SOCK_DGRAM : SOCK_STREAM;
    int port = passive_type == PASSIVE_TCP ? pop3_proxy_state.pop3_proxy_port : pop3_proxy_state.mng_port;
    char * stringed_addr = passive_type == PASSIVE_TCP ? pop3_proxy_state.pop3_proxy_addr : pop3_proxy_state.mng_addr;

    // Si estamos usando la config default, hay que escuchar en los 2 sockets!

    if (strcmp(stringed_addr,"0.0.0.0") == 0 && ip_type == ADDR_IPV6 && passive_type == PASSIVE_TCP
            && pop3_proxy_state.proxy_on_both ){
        stringed_addr = "0::0";
    }

    if (strcmp(stringed_addr,"127.0.0.1") == 0 && ip_type == ADDR_IPV6 && passive_type == PASSIVE_UDP
            && pop3_proxy_state.mng_on_both ){
        stringed_addr = "::1";
    }

    if ((new_socket = socket(net_flag, sock_type, 0)) < 0) // Puede ser 0 por que cerramos el fd 0 para el proxy asi ganamos ud fd mas
    {
        log(ERROR, "Passive: socket failed");
        return -1;
    }

    // Permito que se reuse el addr, funciona sin esto pero es una comodidad
    if (passive_type == PASSIVE_TCP && setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "Passive: set socket options failed");
    }

    // Me aseguro que mis sockets ipv6 no acepter ipv4 tambien
    if (ip_type == ADDR_IPV6 && setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "Passive: set socket options failed");
    }

    if (ip_type == ADDR_IPV4)
    {
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        if (inet_pton(AF_INET, stringed_addr, &address.sin_addr.s_addr) <= 0)
        {
            log(DEBUG, "String address %s doesn't translate to IPv4",stringed_addr);
            close(new_socket);
            return -1;
        }
        address.sin_port =  htons(port);
        if (bind(new_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            log(ERROR, "Passive: bind failed");
            close(new_socket);
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
            log(DEBUG, "String address %s doesn't translate to IPv6",stringed_addr);
            close(new_socket);
            return -1;
        }
        if (bind(new_socket, (struct sockaddr *)&address_6, sizeof(address_6)) < 0)
        {

            log(ERROR, "Passive: bind failed");
            close(new_socket);
            return -1;
        }
    }

    if (passive_type == PASSIVE_TCP && listen(new_socket, MAX_PENDING_CONNECTIONS) < 0)
    {
        log(ERROR, "Passive: listen socket failed");
        close(new_socket);
        return -1;
    }
    else
    {
        log(INFO, "Waiting for %s %s connections on socket %d",ip_type == ADDR_IPV4?"IPv4":"IPV6", passive_type == PASSIVE_TCP?"proxy":"manager", new_socket);
    }
    return new_socket;
}

