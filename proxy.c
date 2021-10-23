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
#include "./utils/include/buffer.h"
#include "./utils/include/selector.h"
#include <sys/signal.h>
#include "./utils/include/stm.h"
#include "./include/proxy.h"

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))

#define TRUE 1
#define FALSE 0
#define DEFAULT_SERVER_PORT 8888
#define DEFAULT_ORIGIN_PORT 110
#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define MAX_PENDING_CONNECTIONS 3 // un valor bajo, para realizar pruebas

const char *err_msg = NULL;

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

struct connection
{
    int fd_client;
    int fd_origin;
  
    struct state_machine stm;

    buffer client_buffer;
    buffer origin_buffer;
};

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct connection *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */

static void proxy_read   (struct selector_key *key);
static void proxy_write  (struct selector_key *key);
static void proxy_block  (struct selector_key *key);
static void proxy_close  (struct selector_key *key);
static const struct fd_handler proxy_handler = {
    .handle_read   = proxy_read,
    .handle_write  = proxy_write,
    .handle_close  = proxy_close,
    .handle_block  = proxy_block,
};

int proxy_create_connection(struct selector_key *key);
int build_passive(IP_TYPE ip_type);

static const struct state_definition client_states[] = {
    {
        .state = RESOLVING,
        .on_arrival = NULL,
        .on_block_ready= NULL,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    },
    {
        .state = CONNECTING,
        .on_arrival = NULL,
        .on_block_ready= NULL,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    },
    {
        .state = COPYING,
        .on_arrival = NULL,
        .on_block_ready= NULL,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    }};



int main(int argc, char *argv[])
{
    unsigned port = DEFAULT_SERVER_PORT;

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

    selector = selector_new(1024);

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

    if ((client_socket = socket(net_flag, SOCK_STREAM, 0)) < 0)  // Puede ser 0 por que cerramos el fd 0 para el proxy asi ganamos ud fd mas
    {
        log(ERROR, "socket failed");
        return -1;
    }

    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    if (setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "set socket options failed");
    }

    if (ip_type == IPV4)
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
    int client_socket = accept(key->fd, (struct sockaddr *)&client_address, &client_address_len);  // TODO : Setear flag de no bloqueante
    if (client_socket < 0)
    {
        log(ERROR,"Cant accept client connection");
        return -1;
    }

   
    // TODO: Borrar este handler por proxy_handler
    const struct fd_handler active_handler = {
        .handle_read = NULL, 
        .handle_write = NULL,
        .handle_close = NULL, // nada que liberar
    };
    selector_status ss = SELECTOR_SUCCESS;
    ss = selector_register(key->s, client_socket, &active_handler, OP_NOOP, NULL); 
    if(ss != SELECTOR_SUCCESS)
    {
        log(ERROR,"Selector error register %s ",selector_error(ss));
        //TODO
    }
   
    log(INFO, "Connection accepted");
    // Falta crear socket entre proxy y servidor origen. Y registrarlo para escritura.
    
    return client_socket;
}


struct connection getNewConnection(int client_fd,int origin_fd){
   struct state_machine stm = {
        .initial = CONNECTING,     // TODO: remplazar por RESOLVING cuando lo tengamos
        .max_state = DONE,
        .states = client_states,
    };

    stm_init(&stm); 

    struct buffer client_buf;
    uint8_t direct_buff[6]; // TODO: Hacer este numero un CTE
    buffer_init(&client_buf, N(direct_buff), direct_buff);

     struct buffer origin_buf;
    uint8_t direct_buff_origin[6]; // TODO: Hacer este numero un CTE
    buffer_init(&origin_buf, N(origin_buf), direct_buff_origin);
    
    struct connection  new_connection ={
        .fd_client = client_fd,
        .stm = stm,
        .fd_origin = origin_fd,
        .client_buffer = client_buf,
        .origin_buffer = origin_buf,
    };


    return new_connection;
}


static void
proxy_read(struct selector_key *key) {
    printf("Llego al read  con fd %d y data %s",key->fd,(char*)key->data);
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_read(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_write(struct selector_key *key) {
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_write(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_block(struct selector_key *key) {
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_block(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_close(struct selector_key *key) {
    // socks5_destroy(ATTACHMENT(key));
}