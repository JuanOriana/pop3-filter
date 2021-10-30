#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
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
#define BUFFSIZE 2048
#define ADDR_STRING_BUFF_SIZE 64
#define MAX_POOL 50

struct copy
{
    // El file descriptor del otro.
    int *fd;

    buffer *read_buffer, *write_buffer;

    fd_interest duplex;

    struct copy *other;
};

typedef struct connection
{
    int client_fd;
    int origin_fd;

    char client_addr_humanized[ADDR_STRING_BUFF_SIZE];
    char origin_addr_humanized[ADDR_STRING_BUFF_SIZE];

    struct state_machine stm;

    buffer *read_buffer;
    buffer *write_buffer;

    struct copy copy_client;

    struct copy copy_origin;

    address_representation origin_address_representation;

    /** Resolución basica la dirección del origin server. */
    struct addrinfo *dns_resolution;

    /** Representa cual es la resolucion que estamos probando actualmente. */
    struct addrinfo *dns_resolution_current_iter;

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

unsigned on_read_ready_copying(struct selector_key *key);
unsigned on_write_ready_copying(struct selector_key *key);
static void connection_destroy_referenced(connection *connection);
static void connection_destroy(connection *connection);
static unsigned on_connection_ready(struct selector_key *key);
static void on_arrival_copying(const unsigned state, struct selector_key *key);
static unsigned dns_resolve_done(struct selector_key *key);

static const struct state_definition client_states[] = {
    {
        .state = RESOLVING,
        .on_block_ready = dns_resolve_done, // se ejecuta cuando se resuelve el nombre
    },
    {
        .state = CONNECTING,
        .on_write_ready = on_connection_ready,
    },
    {
        .state = COPYING,
        .on_arrival = on_arrival_copying,
        .on_departure = NULL,
        .on_read_ready = on_read_ready_copying,
        .on_write_ready = on_write_ready_copying,
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

// static int proxy_connect_to_origin();
struct connection *new_connection(int client_fd, address_representation origin_address_representation);
static void connection_destroy(connection *connection);
static unsigned start_connection_with_origin(fd_selector selector, connection *connection);
static void *dns_resolve_blocking(void *data);
// static unsigned connect_to_host(fd_selector selector, struct connection *proxy);

void proxy_passive_accept(struct selector_key *key)
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
        return ;
    }

    if (set_non_blocking(client_socket) == -1)
    {
        log(ERROR, "Failed on passive-accept");
        close(client_socket);
        return ;
    }

    connection *new_connection_instance = new_connection(client_socket, *origin_representation);
    if (new_connection_instance == NULL)
    {
        log(ERROR, "Couldnt create new connection");
        close(client_socket);
        return ;
    }

    sockaddr_to_human(new_connection_instance->client_addr_humanized, ADDR_STRING_BUFF_SIZE, &client_address);
    log(INFO, "Accepting connection from: %s", new_connection_instance->client_addr_humanized);

    ss = selector_register(key->s, client_socket, &proxy_handler, OP_NOOP, new_connection_instance);
    if (ss != SELECTOR_SUCCESS)
    {
        log(ERROR, "Selector error register %s ", selector_error(ss));
        close(client_socket);
        return ;
        // More checks
    }

    if (origin_representation->type != ADDR_DOMAIN)
    {
        log(DEBUG, "No need to resolve name");
        new_connection_instance->stm.initial = start_connection_with_origin(key->s, new_connection_instance);
        // new_connection_instance->stm.initial = connecting(key->mux, proxy);
        // LOGGING LOGIC
        // SETEO EL ESTADO DE LA STATE MACHINE EN CONNECTING (ME CONECTO DE UNA)
    }
    else
    {
        log(DEBUG, "Trying to resolve name: %s", origin_representation->addr.fqdn);

        struct selector_key *blocking_key = malloc(sizeof(*blocking_key));
        if (key == NULL)
        {
            log(ERROR, "Error resolving name");
            // TODO: manejar el error de malloc
        }

        blocking_key->s = key->s;
        blocking_key->fd = client_socket;
        blocking_key->data = new_connection_instance;

        pthread_t thread_id;
        if (pthread_create(&thread_id, 0, dns_resolve_blocking, blocking_key) == -1)
        {
            log(ERROR, "Error creating new thread");
            // TODO: manejar el error de que no se haya podido crear el thread
            new_connection_instance->stm.initial = CONNECTION_ERROR;
        }
    }

    
}

struct connection *new_connection(int client_fd, address_representation origin_address_representation)
{
    connection *new_connection;

    buffer *read_buf, *write_buf;
    uint8_t *direct_buff, *direct_buff_origin;

    // Verifico si es el primero
    if (connection_pool == NULL)
    {
        new_connection = malloc(sizeof(*new_connection)); // TODO CHECK NULL
        if (new_connection == NULL)
        {
            return NULL;
        }
        direct_buff = malloc(BUFFSIZE);
        direct_buff_origin = malloc(BUFFSIZE);
        read_buf = malloc(sizeof(buffer));
        buffer_init(read_buf, BUFFSIZE, direct_buff); // Errores?
        write_buf = malloc(sizeof(buffer));
        buffer_init(write_buf, BUFFSIZE, direct_buff_origin); // Errores?
    }
    else
    {
        new_connection = connection_pool;
        connection_pool = connection_pool->next;
        read_buf = new_connection->read_buffer;
        write_buf = new_connection->write_buffer;
        buffer_reset(read_buf);
        buffer_reset(write_buf);
    }

    new_connection->client_fd = client_fd;
    new_connection->origin_fd = -1;
    new_connection->read_buffer = read_buf;
    new_connection->write_buffer = write_buf;
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
    // char buff[ADDR_STRING_BUFF_SIZE];

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
        error = 1;

    if (error != 0)
    {
        log(ERROR, "Problem connecting to origin server in on_connection-ready");
        if (SELECTOR_SUCCESS == selector_set_interest(key->s, connection->client_fd, OP_WRITE))
            ret = CONNECTION_ERROR;
        else
            ret = CONNECTION_ERROR;
    }
    else if (SELECTOR_SUCCESS == selector_set_interest(key->s, key->fd, OP_READ))
    {
        struct sockaddr_storage *origin = &connection->origin_address_representation.addr.address_storage;
        sockaddr_to_human(connection->origin_addr_humanized, ADDR_STRING_BUFF_SIZE, origin);
        log(INFO, "Connection established. Client Address: %s; Origin Address: %s.", connection->client_addr_humanized, connection->origin_addr_humanized);
        ret = COPYING;
        // deberia ret = HELLO;
    }
    return ret;
}

static void
proxy_read(struct selector_key *key)
{
    if (key == NULL || key->data == NULL)
    {
        log(DEBUG, "DATA ON KEY NULL");
        return;
    }
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    stm_handler_read(stm, key);

    // if(ERROR == st || DONE == st) {
    //     socksv5_done(key);
    // }
}

static void
proxy_write(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const proxy_state st = stm_handler_write(stm, key);
    if (st == CONNECTION_ERROR || st == DONE)
    {
        //TODO:
        // socksv5_done(key);
    }
}

static void
proxy_block(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const proxy_state st = stm_handler_block(stm, key);

    if (st == CONNECTION_ERROR   || st == DONE)
    {
        //TODO:
        // socksv5_done(key);
    }
}

static void
proxy_close(struct selector_key *key)
{
    connection_destroy_referenced(ATTACHMENT(key));
}

///////////////////////// FUNCIONES DE STATE_DEFINITION /////////////////////////

// RESOLVING

//// resolucion del dominio de forma bloqueante, una vez terminada, el selector es notificado
static void *dns_resolve_blocking(void *data)
{
    struct selector_key *key = (struct selector_key *)data;
    struct connection *connection = ATTACHMENT(key);

    pthread_detach(pthread_self()); // REV
    connection->dns_resolution = 0;
    struct addrinfo flags = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d", connection->origin_address_representation.port);
    getaddrinfo(connection->origin_address_representation.addr.fqdn, buff, &flags, &connection->dns_resolution);
    selector_notify_block(key->s, key->fd);

    free(data);
    return 0;
}

//// on_block_ready
static unsigned dns_resolve_done(struct selector_key *key)
{
    //TODO: NO SE ITERA EN LA RESOLUCION POR LOS DISTINTOS RESULTADOS!!
    struct connection *connection = ATTACHMENT(key);
    if (connection->dns_resolution != 0)
    {
        connection->origin_address_representation.domain = connection->dns_resolution->ai_family;
        connection->origin_address_representation.addr_len = connection->dns_resolution->ai_addrlen;
        memcpy(&connection->origin_address_representation.addr.address_storage,
               connection->dns_resolution->ai_addr,
               connection->dns_resolution->ai_addrlen);
        freeaddrinfo(connection->dns_resolution);
        connection->dns_resolution = 0;
    }
    else
    {
        // proxy->errorSender.message = "-ERR Connection refused.\r\n";
        // if (MUX_SUCCESS != setInterest(key->s, proxy->clientFd, WRITE))
        //     return ERROR;
        // return SEND_ERROR_MSG;
    }

    return start_connection_with_origin(key->s, connection);
}

/**
 *  Destruye y libera un proxyPopv3
 */
static void connection_destroy(connection *connection)
{
    // CLOSE SOCKETS?
    free(&connection->read_buffer->data);
    free(&connection->read_buffer);
    free(&connection->write_buffer->data);
    free(&connection->write_buffer);
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

/////////////////// FUNCIONES DE EL ESTADO COPYING ////////////////////////////////////////

static struct copy *copy_ptr(struct selector_key *key)
{
    struct copy *copy_client = &(ATTACHMENT(key)->copy_client);

    if (*copy_client->fd == key->fd)
    {
        return copy_client;
    }

    return copy_client->other;
}

static void on_arrival_copying(const unsigned state, struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    struct copy *copy_client = &(connection->copy_client);
    struct copy *copy_origin = &(connection->copy_origin);

    copy_client->fd = &connection->client_fd;
    copy_client->read_buffer = connection->read_buffer;
    copy_client->write_buffer = connection->write_buffer;
    copy_client->duplex = OP_READ | OP_WRITE; // TODO: Asignar dependiendo de las reglas de pop 3
    copy_client->other = copy_origin;

    copy_origin->fd = &connection->origin_fd;
    copy_origin->read_buffer = connection->write_buffer;
    copy_origin->write_buffer = connection->read_buffer;
    copy_origin->duplex = OP_READ | OP_WRITE; // TODO: Asignar dependiendo de las reglas de pop 3
    copy_origin->other = copy_client;
}

static fd_interest copy_compute_interests(fd_selector s, struct copy *copy)
{
    fd_interest ret = OP_NOOP;
    if ((copy->duplex & OP_READ) && buffer_can_write(copy->read_buffer))
    {
        ret |= OP_READ;
    }
    if ((copy->duplex & OP_WRITE) && buffer_can_read(copy->write_buffer))
    {
        ret |= OP_WRITE;
    }

    selector_status sel_status = selector_set_interest(s, *copy->fd, ret);
    if (sel_status != SELECTOR_SUCCESS)
    {
        abort();
    }

    return ret;
}

void on_departure_copying(const unsigned state, struct selector_key *key)
{
    printf("ON DEPARTURE");
    connection_destroy(ATTACHMENT(key));
}

// Habria que hacer el manejo de dessetear el FD
unsigned on_read_ready_copying(struct selector_key *key)
{
    struct copy *copy = copy_ptr(key);

    size_t max_size_to_read;
    ssize_t readed;
    buffer *buffer = copy->read_buffer;
    unsigned ret_value = COPYING;

    uint8_t *ptr = buffer_write_ptr(buffer, &max_size_to_read);
    readed = recv(key->fd, ptr, max_size_to_read, 0);
    // log(DEBUG, "Reading from fd=%d , bytes = %d, max_cant = %d", key->fd, readed, max_size_to_read);
    if (readed > 0)
    {
        buffer_write_adv(buffer, readed);  
    }
    else
    {
         //apagar ese fd de lectura
        log(ERROR, "Readed 0 or error. Error: %s",strerror(errno));
            shutdown(*copy->fd, SHUT_RD);
        copy->duplex &= ~OP_READ; // le sacamos el interes de lectura
        if (*copy->other->fd != -1)
        {
            //apagar el otro para escritura
            shutdown(*copy->other->fd, SHUT_WR);
            copy->other->duplex &= ~OP_WRITE;
        }
        //TODO: Ver si no se tendria que retornar a error y cerrar las conexiones que quedaron abiertas.
    }

    copy_compute_interests(key->s, copy);
    copy_compute_interests(key->s, copy->other);

    if (copy->duplex == OP_NOOP)
    {
        ret_value = DONE;
    }

    return ret_value;
}
unsigned on_write_ready_copying(struct selector_key *key)
{

    struct copy *copy = copy_ptr(key);

    size_t max_size_to_write;
    ssize_t sended;
    buffer *buffer = copy->write_buffer;
    unsigned ret_value = COPYING;
    uint8_t *ptr = buffer_read_ptr(buffer, &max_size_to_write);
    sended = send(key->fd, ptr, max_size_to_write, MSG_NOSIGNAL);

    if (sended <= 0)
    {
        //apagar ese fd de escritura
        log(DEBUG, "Sended 0 or error. ERRNO");
        shutdown(*copy->fd, SHUT_WR);
        copy->duplex &= ~OP_WRITE; // le sacamos el interes de escritura
        if (*copy->other->fd != -1)
        {
            //apagar el otro para lectura
            // shutdown(*copy->other->fd,SHUT_RD);
            copy->other->duplex &= ~OP_READ;
        }
    }
    else
    {
        buffer_read_adv(buffer, sended);
    }

    copy_compute_interests(key->s, copy);
    copy_compute_interests(key->s, copy->other);

    if (copy->duplex == OP_NOOP)
    {
        ret_value = DONE;
    }

    return ret_value;
}
