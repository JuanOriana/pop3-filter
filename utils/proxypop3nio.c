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
#include "../include/args.h"
#include "./include/logger.h"
#include "./include/buffer.h"
#include "./include/selector.h"
#include <sys/signal.h>
#include "./include/stm.h"
#include "./include/proxypop3nio.h"

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))

#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define ADDR_STRING_BUFF_SIZE 64
#define MAX_POOL 50

typedef struct connection
{
    int client_fd;
    int origin_fd;

    char client_addr_humanized[ADDR_STRING_BUFF_SIZE];
    char origin_addr_humanized[ADDR_STRING_BUFF_SIZE];

    struct state_machine stm;

    buffer *client_buffer;
    buffer *origin_buffer;

    address_representation origin_address_representation;
    /** Resolución de la dirección del origin server. */
    struct sockaddr_in *origin_resolution;

    /** Cantidad de referencias a este objeto. si es uno se debe destruir. */
    unsigned references;

    struct connection *next;
} connection;

// static unsigned dns_resolve_done(struct selector_key key);

typedef enum
{
    RESOLVING,
    CONNECTING,
    COPYING,
    DONE,
    CONNECTION_ERROR
} proxy_state;

typedef struct state_definition state_definition;

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ((struct connection *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */

struct connection *connection_pool;
int connection_pool_size = 0;
extern struct pop3_proxy_args pop3_proxy_args;

static void proxy_read(struct selector_key *key);
static void proxy_write(struct selector_key *key);
static void proxy_block(struct selector_key *key);
static void proxy_close(struct selector_key *key);
static const struct fd_handler proxy_handler = {
    .handle_read = proxy_read,
    .handle_write = proxy_write,
    .handle_close = proxy_close,
    .handle_block = proxy_block,
};

static const struct state_definition client_states[] = {
    {
        .state = RESOLVING,
        .on_arrival = NULL, // resolver nombre e irse a connecting
        //.on_block_ready = dns_resolve_done, // se ejecuta cuando se resuelve el nombre
        // CREO que no hay que pasarle nada "on_arrival", el selector notifica cuando termino el "dns_resolve_blocking"
    },
    {
        .state = CONNECTING,
        .on_arrival = NULL, // crear la estructura de la conexion
        .on_block_ready = NULL,
    },
    {
        .state = COPYING,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    },
    {
        .state = DONE,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    },
    {
        .state = CONNECTION_ERROR,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    }};

static int proxy_connect_to_origin();
struct connection *new_connection(int client_fd, address_representation origin_address_representation);
static void connection_destroy(connection *connection);
static unsigned start_connection_with_origin(fd_selector selector, connection *connection);

static int
proxy_connect_to_origin()
{
    int origin_socket = -1, opt;
    struct sockaddr_in origin_addr;
    if ((origin_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        log(ERROR, "Origin: Socket failed");
        return -1;
    }
    // set master socket to allow multiple connections , this is just a good habit, it will work without this
    if (setsockopt(origin_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0)
    {
        log(ERROR, "Origin: set socket options failed");
        return -1;
    }

    origin_addr.sin_family = AF_INET;
    origin_addr.sin_port = htons(pop3_proxy_args.origin_port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &origin_addr.sin_addr) <= 0)
    {
        log(ERROR, "Origin: Invalid address/ Address not supported \n");
        return -1;
    }

    if (connect(origin_socket, (struct sockaddr *)&origin_addr, sizeof(origin_addr)) < 0)
    {
        log(ERROR, "Origin: Connection failed \n");
        return -1;
    }

    log(INFO, "origin: %d", origin_socket);
    return origin_socket;
}

int proxy_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_address; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t client_address_len = sizeof(client_address);
    address_representation *origin_representation = (address_representation *)key->data;
    selector_status ss = SELECTOR_SUCCESS;

    // Wait for a client to connect
    int client_socket = accept(key->fd, (struct sockaddr *)&client_address, &client_address_len); // TODO : Setear flag de no bloqueante
    if (client_socket < 0)
    {
        log(ERROR, "Cant accept client connection");
        return -1;
    }

    if (set_non_blocking(client_socket) == -1)
    {
        log(ERROR, "Failed on passive-accept");
        close(client_socket);
        return -1;
    }

    connection *new_connection_instance = new_connection(client_socket, *origin_representation);
    if (new_connection_instance == NULL)
    {
        log(ERROR, "Couldnt create new connection");
        close(client_socket);
        return -1;
    }

    sockaddr_to_human(new_connection_instance->client_addr_humanized, ADDR_STRING_BUFF_SIZE, &client_address);
    log(INFO, "Accepting connection from: %s", new_connection_instance->client_addr_humanized);

    ss = selector_register(key->s, client_socket, &proxy_handler, OP_NOOP, NULL);
    if (ss != SELECTOR_SUCCESS)
    {
        log(ERROR, "Selector error register %s ", selector_error(ss));
        close(client_socket);
        return -1;
        // More checks
    }

    if (origin_representation->type != ADDR_DOMAIN)
    {
        log(DEBUG, "No need to resolve name");
        new_connection_instance->stm.initial = start_connection_with_origin(key->s, new_connection_instance);
        //new_connection_instance->stm.initial = connecting(key->mux, proxy);
        //LOGGING LOGIC
        //SETEO EL ESTADO DE LA STATE MACHINE EN CONNECTING (ME CONECTO DE UNA)
    }
    else
    {
        log(DEBUG, "Trying to resolve name: %s", origin_representation->addr.fqdn);
    }

    log(INFO, "Connection accepted");

    return client_socket;
}

struct connection *new_connection(int client_fd, address_representation origin_address_representation)
{
    connection *new_connection;

    buffer *client_buf, *origin_buf;
    uint8_t direct_buff[BUFFSIZE], direct_buff_origin[BUFFSIZE]; // TODO: Hacer este numero un CTE

    //Verifico si es el primero
    if (connection_pool == NULL)
    {
        new_connection = malloc(sizeof(*new_connection)); // TODO CHECK NULL
        if (new_connection == NULL)
        {
            return NULL;
        }
        client_buf = malloc(sizeof(buffer));
        buffer_init(client_buf, N_BUFFER(direct_buff), direct_buff); // Errores?
        origin_buf = malloc(sizeof(buffer));
        buffer_init(origin_buf, N_BUFFER(direct_buff_origin), direct_buff_origin); // Errores?
    }
    else
    {
        new_connection = connection_pool;
        connection_pool = connection_pool->next;
        client_buf = new_connection->client_buffer;
        origin_buf = new_connection->origin_buffer;
        buffer_reset(client_buf);
        buffer_reset(origin_buf);
    }

    new_connection->client_fd = client_fd;
    new_connection->origin_fd = -1;
    new_connection->client_buffer = client_buf;
    new_connection->origin_buffer = origin_buf;
    new_connection->origin_address_representation = origin_address_representation;
    new_connection->next = NULL;
    new_connection->references = 1;

    new_connection->stm.initial = RESOLVING;
    new_connection->stm.max_state = CONNECTION_ERROR;
    new_connection->stm.states = client_states;
    stm_init(&new_connection->stm);

    return new_connection;
}

/** 
 * Intenta establecer una conexión con el origin server. 
 */
static unsigned start_connection_with_origin(fd_selector selector, connection *connection)
{
    address_representation origin_address_representation = connection->origin_address_representation;

    connection->origin_fd = socket(origin_address_representation.domain, SOCK_STREAM, IPPROTO_TCP);

    if (connection->origin_fd == -1)
        goto finally;
    if (set_non_blocking(connection->origin_fd) == -1)
        goto finally;

    if (connect(connection->origin_fd, (const struct sockaddr *)&origin_address_representation.addr.address_storage,
                origin_address_representation.addr_len) == -1)
    {
        if (errno == EINPROGRESS)
        {
            log(DEBUG, "In progress");
            /**
             * Polleando cliente
             */
            selector_status ss = selector_set_interest(selector, connection->client_fd, OP_NOOP);
            if (ss != SELECTOR_SUCCESS)
                goto finally;

            /** Esperamos la conexion en el nuevo socket. */
            ss = selector_register(selector, connection->origin_fd, &proxy_handler, OP_WRITE, connection);
            if (ss != SELECTOR_SUCCESS)
                goto finally;

            connection->references += 1;
        }
    }
    else
    {
        /**
         * Estamos conectados sin esperar... no parece posible
         * Saltaríamos directamente a COPY.
         */
        log(DEBUG, "Not waiting ???");
    }
    return CONNECTING;

finally:
    log(ERROR, "Cant connect to origin server.");
    return ERROR;
}

static unsigned on_connection_ready(struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = ERROR;
    char buff[ADDR_STRING_BUFF_SIZE];

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
        error = 1;

    if (error != 0)
    {
        log(ERROR, "Problem connecting to origin server in on_connection-ready");
        if (SELECTOR_SUCCESS == selector_set_interest(key->s, connection->client_fd, OP_WRITE))
            ret = ERROR;
        else
            ret = ERROR;
    }
    else if (SELECTOR_SUCCESS == selector_set_interest(key->s, key->fd, OP_READ))
    {
        struct sockaddr_storage *origin = &connection->origin_address_representation.addr.address_storage;
        sockaddr_to_human(connection->origin_addr_humanized, ADDR_STRING_BUFF_SIZE, origin);
        log(INFO, "Connection established. Client Address: %s; Origin Address: %s.", connection->client_addr_humanized, connection->origin_addr_humanized);
        ret = ERROR;
        //deberia ret = HELLO;
    }
    return ret;
}

static void
proxy_read(struct selector_key *key)
{
    printf("Llego al read  con fd %d y data %s", key->fd, (char *)key->data);
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_read(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_write(struct selector_key *key)
{
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_write(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_block(struct selector_key *key)
{
    // struct state_machine *stm   = &ATTACHMENT(key)->stm;
    // const enum socks_v5state st = stm_handler_block(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_close(struct selector_key *key)
{
    // socks5_destroy(ATTACHMENT(key));
}

///////////////////////// FUNCIONES DE STATE_DEFINITION /////////////////////////

// RESOLVING

//// resolucion del dominio de forma bloqueante, una vez terminada, el selector es notificado
// static void *dns_resolve_blocking(void *data)
// {
//     struct selector_key key = (struct selector_key *)data;
//     struct connection *proxy = ATTACHMENT(key);

//     pthread_detach(pthread_self()); // REV
//     proxy->origin_resolution = 0;
//     struct addrinfo hints = {
//         .ai_family = AF_UNSPEC,
//         /** Permite IPv4 o IPv6. */
//         .ai_socktype = SOCK_STREAM,
//         .ai_flags = AI_PASSIVE,
//         .ai_protocol = 0,
//         .ai_canonname = NULL,
//         .ai_addr = NULL,
//         .ai_next = NULL,
//     };

//     char buff[7];
//     snprintf(buff, sizeof(buff), "%d", proxy->origin_address_information.port);
//     getaddrinfo(proxy->origin_address_information.addr.fqdn, buff, &hints, &proxy->origin_resolution);
//     selector_notify_block(key->s, key->fd);

//     free(data);
//     return 0;
// }

// //// on_block_ready
// static unsigned dns_resolve_done(struct selector_key key)
// {
//     struct connection *proxy = ATTACHMENT(key);
//     if (proxy->origin_resolution != 0)
//     {
//         proxy->origin_address_information.domain = proxy->origin_resolution->ai_family;
//         proxy->origin_address_information.addr_length = proxy->origin_resolution->ai_addrlen;
//         memcpy(&proxy->origin_address_information.addr.addr_storage,
//                proxy->origin_resolution->ai_addr,
//                proxy->origin_resolution->ai_addrlen);
//         freeaddrinfo(proxy->origin_resolution);
//         proxy->origin_resolution = 0;
//     }
//     else
//     {
//         // proxy->errorSender.message = "-ERR Connection refused.\r\n";
//         // if (MUX_SUCCESS != setInterest(key->s, proxy->clientFd, WRITE))
//         //     return ERROR;
//         // return SEND_ERROR_MSG;
//     }

//     return connect_to_host(key->s, proxy);
// }

// /**
//  * Intenta establecer una conexión con el origin server.
//  */
// static unsigned connect_to_host(fd_selector selector, struct connection *proxy)
// {
// }

/**
 *  Destruye y libera un proxyPopv3
 */
static void connection_destroy(connection *connection)
{
    //CLOSE SOCKETS?
    free(&connection->client_buffer->data);
    free(&connection->client_buffer);
    free(&connection->origin_buffer->data);
    free(&connection->origin_buffer);
    free(connection);
}

static void connection_destroy_referenced(connection *connection)
{
    if (connection == NULL)
    {
        // nada para hacer
    }
    else if (connection->references == 1)
    {
        if (connection != NULL)
        {
            if (connection_pool_size < MAX_POOL)
            {
                connection->next = connection_pool;
                connection_pool = connection;
                connection_pool_size++;
            }
            else
            {
                connection_destroy(connection);
            }
        }
    }
    else
    {
        connection->references -= 1;
    }
}

void connection_pool_destroy()
{
    connection *curr, *next;
    for (curr = connection_pool; curr != NULL; curr = next)
    {
        next = curr->next;
        connection_destroy(curr);
    }
}