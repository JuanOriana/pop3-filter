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
#include <fcntl.h>
#include "../include/args.h"
#include "../utils/include/logger.h"
#include "../utils/include/buffer.h"
#include "../utils/include/selector.h"
#include <sys/signal.h>
#include "../utils/include/stm.h"
#include "./include/proxypop3nio.h"
#include "../parsers/include/hello_parser.h"

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))

#define MAX_SOCKETS 30
#define BUFFSIZE 2048
#define ADDR_STRING_BUFF_SIZE 64
#define MAX_POOL 50

//Patch for MacOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif


typedef enum {
    CLIENT,
    ORIGIN,
    FILTER
}targets;

struct copy
{
    // El file descriptor del otro.
    int *fd;

    buffer *read_buffer, *write_buffer;

    fd_interest duplex;

    targets target;

    struct copy *other;
};

struct hello_struct {
    buffer  buffer;
    hello_parser hello_parser;
};

struct session{
    time_t last_used;
};

typedef struct error_data {
    char * err_msg;
    size_t msg_len;
    size_t msg_sent_size; 
} error_data;

typedef enum
{
    FILTER_START,
    FILTER_WORKING,
    FILTER_FINISHED_SENDING,
    FILTER_ENDING,
    FILTER_CLOSE
}filter_state;

struct filter_data{
    int     write_pipe[2];
    int     read_pipe[2];
    pid_t   slave_proc_pid;
    filter_state state;
};

typedef struct connection
{
    int client_fd;
    int origin_fd;

    struct session session;
    struct filter_data filter;

    char client_addr_humanized[ADDR_STRING_BUFF_SIZE];
    char origin_addr_humanized[ADDR_STRING_BUFF_SIZE];

    struct state_machine stm;

    buffer *read_buffer;
    buffer *write_buffer;
    buffer *filter_buffer;

    struct hello_struct hello_client;
    struct copy copy_client;

    struct hello_struct hello_origin;
    struct copy copy_origin;

    struct copy copy_filter;

    address_representation origin_address_representation;

    /** Resolución basica la dirección del origin server. */
    struct addrinfo *dns_resolution;

    /** Representa cual es la resolucion que estamos probando actualmente. */
    struct addrinfo *dns_resolution_current_iter;

    /** Cantidad de referencias a este objeto. si es uno se debe destruir. */
    unsigned references;

    error_data error_data;

    struct connection *next;
} connection;

// static unsigned dns_resolve_done(struct selector_key key);

typedef enum
{
    RESOLVING,
    CONNECTING,
    HELLO,
    COPYING,
    DONE,
    ERROR_ST,
    ERROR_W_MESSAGE_ST
} proxy_state;



typedef struct state_definition state_definition;

/** obtiene el struct (connection *) desde la llave de selección  */
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
static void proxy_time_out(struct selector_key *key);
static void proxy_done(struct selector_key *key);

static const struct fd_handler proxy_handler = {
    .handle_read = proxy_read,
    .handle_write = proxy_write,
    .handle_close = proxy_close,
    .handle_block = proxy_block,
    .handle_time_out = proxy_time_out,
};


unsigned on_read_ready_copying(struct selector_key *key);
unsigned on_write_ready_copying(struct selector_key *key);
unsigned on_read_ready_hello(struct selector_key *key);
unsigned on_write_ready_hello(struct selector_key *key);
static void connection_destroy_referenced(connection *connection);
static void connection_destroy(connection *connection);
static unsigned on_connection_ready(struct selector_key *key);
static void on_arrival_copying(const unsigned state, struct selector_key *key);
static void on_arrival_hello(const unsigned state, struct selector_key *key);
static unsigned dns_resolve_done(struct selector_key *key);
static unsigned send_err_msg(struct selector_key *key);

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
        .state = HELLO,
        .on_arrival = on_arrival_hello,
        .on_read_ready = on_read_ready_hello,
        .on_write_ready = on_write_ready_hello,

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
        .state = ERROR_ST,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = NULL,
    },
    {
        .state = ERROR_W_MESSAGE_ST,
        .on_departure = NULL,
        .on_read_ready = NULL,
        .on_write_ready = send_err_msg,
    }};


struct connection *new_connection(int client_fd, address_representation origin_address_representation);
static void connection_destroy(connection *connection);
static unsigned start_connection_with_origin(fd_selector selector, connection *connection);
static void *dns_resolve_blocking(void *data);
static void *connection_close_select(struct selector_key *key);


void proxy_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_address; // Client address
    // Set length of client address structure (in-out parameter)
    socklen_t client_address_len = sizeof(client_address);
    address_representation *origin_representation = (address_representation *)key->data;
    selector_status ss = SELECTOR_SUCCESS;
    connection *new_connection_instance = NULL;
    char * err_msg;

    // Wait for a client to connect
    int client_socket = accept(key->fd, (struct sockaddr *)&client_address, &client_address_len); // TODO : Setear flag de no bloqueante
    if (client_socket < 0)
    {
        err_msg = "cant accept client connection";
        goto passivefinally;
    }

    if (set_non_blocking(client_socket) == -1)
    {
        err_msg = "failed on passive-accept";
        goto passivefinally;

    }

    new_connection_instance = new_connection(client_socket, *origin_representation);
    if (new_connection_instance == NULL)
    {
        err_msg = "couldnt create new connection";
        goto passivefinally;

    }

    sockaddr_to_human(new_connection_instance->client_addr_humanized, ADDR_STRING_BUFF_SIZE, &client_address);
    log(INFO, "Accepting connection from: %s", new_connection_instance->client_addr_humanized);

    ss = selector_register(key->s, client_socket, &proxy_handler, OP_NOOP, new_connection_instance);
    if (ss != SELECTOR_SUCCESS)
    {
        err_msg = "selector error register";
        goto passivefinally;

    }

    if (origin_representation->type != ADDR_DOMAIN)
    {
        log(DEBUG, "No need to resolve name");
        new_connection_instance->stm.initial = start_connection_with_origin(key->s, new_connection_instance);
    }
    else
    {
        log(DEBUG, "Trying to resolve name: %s", origin_representation->addr.fqdn);

        struct selector_key *blocking_key = malloc(sizeof(*blocking_key));
        if (blocking_key == NULL)
        {
            err_msg = "can't create key for name resolution";
            selector_unregister_fd(key->s,client_socket);
            goto passivefinally;
        }

        blocking_key->s = key->s;
        blocking_key->fd = client_socket;
        blocking_key->data = new_connection_instance;

        pthread_t thread_id;
        if (pthread_create(&thread_id, 0, dns_resolve_blocking, blocking_key) == -1)
        {
            new_connection_instance->error_data.err_msg="-ERR can't resolve destination.\r\n";
            if(SELECTOR_SUCCESS != selector_set_interest(key->s, new_connection_instance->client_fd, OP_WRITE)){
                err_msg = "unable to create a new thread";
                selector_unregister_fd(key->s,client_socket);
                goto passivefinally;
            }
            new_connection_instance->stm.initial = ERROR_W_MESSAGE_ST;
        }
    }
    return;
passivefinally:
    if (err_msg != NULL)
        log(ERROR,"Passive accept fail: %s",err_msg);
    if (client_socket != -1)
        close(client_socket);
    if (new_connection_instance != NULL){
        connection_destroy_referenced(new_connection_instance);
    }
}

struct connection *new_connection(int client_fd, address_representation origin_address_representation)
{
    connection *new_connection;

    buffer *read_buf, *write_buf,*filter_buf;
    uint8_t *direct_buff, *direct_buff_origin,*direct_buff_filter;

    // Verifico si es el primero
    if (connection_pool == NULL)
    {
        new_connection = malloc(sizeof(*new_connection)); // TODO CHECK NULL
        if (new_connection == NULL)
        {
            return NULL;
        }
        direct_buff = malloc(BUFFSIZE);
        direct_buff_filter = malloc(BUFFSIZE);
        direct_buff_origin = malloc(BUFFSIZE);
        read_buf = malloc(sizeof(buffer));
        buffer_init(read_buf, BUFFSIZE, direct_buff); // Errores?
        write_buf = malloc(sizeof(buffer));
        buffer_init(write_buf, BUFFSIZE, direct_buff_origin); // Errores?
        filter_buf = malloc(sizeof(buffer));
        buffer_init(filter_buf, BUFFSIZE, direct_buff_filter); // Errores?
    }
    else
    {
        new_connection = connection_pool;
        connection_pool = connection_pool->next;
        read_buf = new_connection->read_buffer;
        write_buf = new_connection->write_buffer;
        filter_buf = new_connection->filter_buffer;
        buffer_reset(read_buf);
        buffer_reset(write_buf);
        buffer_reset(filter_buf);
    }

    new_connection->client_fd = client_fd;
    new_connection->origin_fd = -1;
    new_connection->read_buffer = read_buf;
    new_connection->write_buffer = write_buf;
    new_connection->filter_buffer = filter_buf;
    new_connection->origin_address_representation = origin_address_representation;
    new_connection->next = NULL;
    new_connection->references = 1;
    memset(&new_connection->error_data,0,sizeof(new_connection->error_data));

    new_connection->stm.initial = RESOLVING;
    new_connection->stm.max_state = ERROR_W_MESSAGE_ST;
    new_connection->stm.states = client_states;
    stm_init(&new_connection->stm);

    new_connection->filter.slave_proc_pid = -1;

    new_connection->session.last_used = time(NULL);

    return new_connection;
}

/**
 * Intenta establecer una conexión con el origin server.
 */
static unsigned start_connection_with_origin(fd_selector selector, connection *connection)
{
    address_representation origin_address_representation = connection->origin_address_representation;
    connection->origin_fd = socket(origin_address_representation.domain, SOCK_STREAM, IPPROTO_TCP);
    log(DEBUG, "origin socket = %d",connection->origin_fd);
    if (connection->origin_fd == -1)
        goto connectionfinally;
    if (set_non_blocking(connection->origin_fd) == -1)
        goto connectionfinally;

    if (connect(connection->origin_fd, (const struct sockaddr *)&origin_address_representation.addr.address_storage,
                origin_address_representation.addr_len) == -1)
    {
        if (errno == EINPROGRESS)
        {
            log(DEBUG, "Connecting in progress");
            selector_status ss = selector_set_interest(selector, connection->client_fd, OP_NOOP);
            if (ss != SELECTOR_SUCCESS)
                goto connectionfinally;
            // Hay que usar OP_WRITE para esperar la conexion.
            ss = selector_register(selector, connection->origin_fd, &proxy_handler, OP_WRITE, connection);
            if (ss != SELECTOR_SUCCESS)
                goto connectionfinally;

            connection->references += 1;
        }
    }
    else
    {
        /**
         * Estamos conectados sin esperar... no parece posible
         */
        log(DEBUG, "Not waiting ???");
    }
    return CONNECTING;

connectionfinally:
    connection->dns_resolution_current_iter = connection->dns_resolution_current_iter->ai_next;
    // This only makes sense if it's the last iteration (drowning the selector)
    if (connection->dns_resolution_current_iter == NULL) {
        log(ERROR, "Cant connect to origin server.");
        connection->error_data.err_msg = "-ERR Connection refused.\r\n";
        if (SELECTOR_SUCCESS != selector_set_interest(selector, connection->client_fd, OP_WRITE)) {
            return ERROR_ST;
        }
        return ERROR_W_MESSAGE_ST;
    }
    return ERROR_ST;
}

static unsigned on_connection_ready(struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = ERROR_ST;

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
        error = 1;

    if (error != 0)
    {
        log(ERROR, "Problem connecting to origin server in on_connection-ready");
        connection->error_data.err_msg = "-ERR Connection refused.\r\n";
        if (SELECTOR_SUCCESS == selector_set_interest(key->s, connection->client_fd, OP_WRITE)){
            ret = ERROR_W_MESSAGE_ST;
        }
        else{
            ret = ERROR_ST;
        }
    }
    else if (SELECTOR_SUCCESS == selector_set_interest(key->s, key->fd, OP_READ))
    {
        struct sockaddr_storage *origin = &connection->origin_address_representation.addr.address_storage;
        sockaddr_to_human(connection->origin_addr_humanized, ADDR_STRING_BUFF_SIZE, origin);
        log(INFO, "Connection successful. Client Address: %s; Origin Address: %s.", connection->client_addr_humanized, connection->origin_addr_humanized);
        ret = HELLO; // estaba copying
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
    ATTACHMENT(key)->session.last_used = time(NULL); // Update the last time used
    const proxy_state st =  stm_handler_read(stm, key);

    if(ERROR_ST == st || DONE == st) {
         proxy_done(key);
    }
}

static void
proxy_write(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    ATTACHMENT(key)->session.last_used = time(NULL); // Update the last time used
    const proxy_state st = stm_handler_write(stm, key);
    if (st == ERROR_ST || st == DONE)
    {
        proxy_done(key);
    }
}

static void proxy_time_out(struct selector_key *key){
    connection * connection = ATTACHMENT(key);

    if(connection!= NULL && difftime(time(NULL),connection->session.last_used) >= TIMEOUT){
        log(DEBUG,"Destroying connection for inactivity");
        // connection_destroy(ATTACHMENT(key)); /// TODO: ARREGLAR EL PROXY_DESTROY
        selector_unregister_fd(key->s,connection->origin_fd);
        selector_unregister_fd(key->s,connection->client_fd);
        close(connection->client_fd);
        close(connection->origin_fd);
    }
}

static void
proxy_block(struct selector_key *key)
{
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const proxy_state st = stm_handler_block(stm, key);

    if (st == ERROR_ST || st == DONE)
    {
        proxy_done(key);
    }
}

static void
proxy_close(struct selector_key *key)
{
    connection_destroy_referenced(ATTACHMENT(key));
}

static void proxy_done(struct selector_key *key){
    connection * connection = ATTACHMENT(key);

    if (connection->client_fd != -1){
        selector_unregister_fd(key->s,connection->client_fd);
        close(connection->client_fd);
    }
    if (connection->origin_fd != -1){
        selector_unregister_fd(key->s,connection->origin_fd);
        close(connection->origin_fd);

    }
}

///////////////////////// FUNCIONES DE STATE_DEFINITION /////////////////////////

// RESOLVING

//// resolucion del dominio de forma bloqueante, una vez terminada, el selector es notificado
static void *dns_resolve_blocking(void *data)
{
    struct selector_key *key = (struct selector_key *)data;
    struct connection *connection = ATTACHMENT(key);

    pthread_detach(pthread_self());
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
    connection->dns_resolution_current_iter = connection->dns_resolution;
    selector_notify_block(key->s, key->fd);
    free(data);
    return 0;
}

//// on_block_ready
static unsigned dns_resolve_done(struct selector_key *key)
{
    struct connection *connection = ATTACHMENT(key);
    int ret_val = ERROR_ST;

    while (connection->dns_resolution_current_iter != NULL)
    {
        // connection->origin_fd = new_server_socket;
        connection->origin_address_representation.domain = connection->dns_resolution_current_iter->ai_family;
        connection->origin_address_representation.addr_len = connection->dns_resolution_current_iter->ai_addrlen;
        memcpy(&connection->origin_address_representation.addr.address_storage,
               connection->dns_resolution_current_iter->ai_addr,
               connection->dns_resolution_current_iter->ai_addrlen);
        ret_val = start_connection_with_origin(key->s,connection);
        if (ret_val != ERROR_ST && ret_val != ERROR_W_MESSAGE_ST)
            break;
    }
    freeaddrinfo(connection->dns_resolution);
    connection->dns_resolution = 0;
    return ret_val;
}

/**
 *  Destruye y libera un proxyPopv3
 */
static void connection_destroy(connection *connection)
{
    // CLOSE SOCKETS? 
    // TODO: Ver si metemos el destroy filter aca
    log(DEBUG,"Closing connection");
    free(connection->read_buffer->data);
    free(connection->read_buffer);

    free(connection->write_buffer->data);
    free(connection->write_buffer);
    free(connection);
}

static void connection_destroy_referenced(connection *connection)
{
    if (connection == NULL)
    {
        log(ERROR,"Received NULL connection");   // nada para hacer
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
        // connection_destroy(connection); // TODO: Ver por que esto no estaba aca
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

/////////////////// FUNCIONES DEL ESTADO HELLO ////////////////////////////////////////////

static void on_arrival_hello(const unsigned state, struct selector_key *key){
    connection * connection = ATTACHMENT(key);
    struct hello_struct * hello_struct = &connection->hello_origin;

    hello_parser_init(&hello_struct->hello_parser);
    hello_struct->buffer = *connection->write_buffer;
    connection->hello_client.buffer = *connection->read_buffer;
}

unsigned on_read_ready_hello(struct selector_key *key){
    connection * connection = ATTACHMENT(key);
    struct hello_struct * hello_origin = &connection->hello_origin;
    struct hello_struct * hello_client = &connection->hello_client;
    hello_state hello_state = HELLO_FINISHED_CORRECTLY;
    uint8_t * ptr,*ptr_write;
    size_t size;
    ssize_t readed;

    ptr = buffer_write_ptr(&hello_origin->buffer,&size);
   
    readed = recv(key->fd,ptr,size,0);
    
    ptr_write = buffer_write_ptr(&hello_client->buffer,&size);

    memcpy(ptr_write,ptr,readed);
    buffer_write_adv(&hello_client->buffer,readed);


    if(readed > 0){
        buffer_write_adv(&hello_origin->buffer,readed);

        hello_state = parse_hello(&hello_origin->hello_parser,&hello_origin->buffer);
        

        if(hello_state== HELLO_FINISHED_CORRECTLY){

            if((SELECTOR_SUCCESS != selector_set_interest(key->s,connection->origin_fd,OP_NOOP)) || (SELECTOR_SUCCESS!=selector_set_interest(key->s,connection->client_fd, OP_WRITE))) // Despues del hello el proximo que habla es el cliente.
            {
                return ERROR_ST;
            }
            log(DEBUG,"Hello read finished succesfully");
            return HELLO;
        }else if(hello_state == HELLO_FAILED){
            log(ERROR,"Hello failed");
            connection->error_data.err_msg = "-ERR HELLO FAILED.\r\n";
            if (SELECTOR_SUCCESS != selector_set_interest(key->s, connection->client_fd, OP_WRITE))
                return ERROR_ST;
            return ERROR_W_MESSAGE_ST;
        }
        return HELLO;

    }else{
        shutdown(key->fd,SHUT_RD);
        log(ERROR,"Hello recv recieved 0 or error.")
        connection->error_data.err_msg = "-ERR HELLO FAILED.\r\n";
        if (SELECTOR_SUCCESS != selector_set_interest(key->s, connection->client_fd, OP_WRITE))
            return ERROR_ST;
        return ERROR_W_MESSAGE_ST;
    }
}

unsigned on_write_ready_hello(struct selector_key *key){
    struct hello_struct * hello_origin = &ATTACHMENT(key)->hello_origin;
    struct hello_struct * hello_client = &ATTACHMENT(key)->hello_client;
    struct connection * connection = ATTACHMENT(key);
    buffer * buffer = &hello_client->buffer;
    uint8_t * ptr;
    size_t size;
    ssize_t sended;

    ptr = buffer_read_ptr(buffer,&size);
    sended = send(key->fd,ptr,size,MSG_NOSIGNAL);

    if(sended>0){
        buffer_read_adv(buffer,sended);
        if(hello_finished(hello_origin->hello_parser.current_state)){
            log(DEBUG,"Hello finished succesfully");
            if((SELECTOR_SUCCESS == selector_set_interest(key->s,connection->origin_fd,OP_NOOP))&& (SELECTOR_SUCCESS == selector_set_interest(key->s,connection->client_fd,OP_READ))) // TODO: CHEQUEAR SI ES CORRECTO ESTE INTERES DE CLIENT
            {
                return COPYING; //TODO: deberia ser COMMANDS
            }else{
                log(ERROR,"Set interests hello failed");
                return ERROR_ST;
            }
        }else if(!buffer_can_read(buffer) && (SELECTOR_SUCCESS == selector_set_interest(key->s,connection->origin_fd,OP_READ)) && (SELECTOR_SUCCESS == selector_set_interest(key->s,connection->client_fd,OP_NOOP))){
            return HELLO;
        }
    }
    log(ERROR,"sended 0");
    return ERROR_ST;
}

/////////////////// FUNCIONES DEL FILTER //////////////////////////////////////////////////

static void filter_working_blocking(struct selector_key *key){
    //TODO
}

static void filter_init(struct selector_key * key){
    connection * connection = ATTACHMENT(key);
    struct filter_data * filter = &connection->filter;
    pid_t pid;

    for(int i=0;i<2;i++){
        filter->write_pipe[i]=-1;
        filter->read_pipe[i]=-1;
    }

    if(pipe(filter->write_pipe)<0){
        log(ERROR,"Error when creating writing pipe for filter");
    }

    if(pipe(filter->read_pipe)<0){
        log(ERROR,"Error when creating writing pipe for filter");
    }

    if((pid = fork()) == 0){
        filter->slave_proc_pid = -1;

        //Cerramos la salida, entrada y salida de errores estandar para el proceso hijo ya que le corresponde al padre en este caso.
        close(STDOUT_FILENO);
        close(STDIN_FILENO);
        // close(STDERR_FILENO);
        //Cerramos las partes del pipe que no vamos a utilizar
        close(filter->read_pipe[1]); // Recordar pipe[1] es para escritura
        close(filter->write_pipe[0]);

        //Redireccionamos la entrada estandar al pipe de lectura del proceso y la salida estandar al pipe del proceso
        if((dup2(filter->read_pipe[0],STDIN_FILENO)<0) || (dup2(filter->write_pipe[1],STDOUT_FILENO)<0)){
            log(ERROR,"Error when dup2 on filter process");
        }

        open(pop3_proxy_args.error_file,O_WRONLY | O_APPEND); // O_APPEND indica que escriba a partir del final del archivo

        //TODO: Setear variables de entorno
         log(ERROR,"EXECLL command");
        if(execl("/bin/sh","sh","-c",pop3_proxy_args.filter,(char * )0) < 0){
            log(ERROR,"Executing command");
            close(filter->read_pipe[0]);
            close(filter->write_pipe[1]);
        }

        filter_working_blocking(key);

    }else{
        filter->slave_proc_pid = pid;
        
        //Cerramos las partes del pipe que no vamos a utilizar
        close(filter->write_pipe[1]);
        close(filter->read_pipe[0]);

        log(DEBUG," set not blocking to filter sockets on proxy");
        if( (selector_fd_set_nio(filter->write_pipe[0]) < 0) || (selector_fd_set_nio(filter->read_pipe[1]) < 0)){
            log(ERROR,"Failed to set not blocking to filter sockets on proxy");
            // TODO SI HAY QUE ABORTAR LA CONEXCION O QUE.
        }

        if( (selector_register(key->s,filter->write_pipe[0],&proxy_handler,OP_NOOP,connection)!= SELECTOR_SUCCESS) || (selector_register(key->s,filter->read_pipe[1],&proxy_handler,OP_NOOP,connection)!= SELECTOR_SUCCESS) )
        {
            log(ERROR,"Failed to register filter fds");
            // TODO : VER Q MANEJO HACER ACA
        }

        connection->references+=2;

    }

}

/////////////////// FUNCIONES DE EL ESTADO COPYING ////////////////////////////////////////

static struct copy *copy_ptr(struct selector_key *key)
{
    struct copy *copy_client = &(ATTACHMENT(key)->copy_client);
    struct copy *copy_origin = &(ATTACHMENT(key)->copy_origin);
    struct copy *copy_filter = &(ATTACHMENT(key)->copy_filter);


    if (*copy_client->fd == key->fd)
    {
        return copy_client;
    }else if(*copy_origin->fd == key->fd){
        return copy_origin;
    }

    return copy_filter;
}

static void on_arrival_copying(const unsigned state, struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    struct copy *copy_client = &(connection->copy_client);
    struct copy *copy_origin = &(connection->copy_origin);
    struct copy *copy_filter = &(connection->copy_filter);

    copy_client->fd = &connection->client_fd;
    copy_client->read_buffer = connection->read_buffer;
    copy_client->write_buffer = connection->write_buffer;
    copy_client->duplex = OP_READ | OP_WRITE; // TODO: Asignar dependiendo de las reglas de pop 3
    copy_client->other = copy_origin;
    copy_client->target = CLIENT;

    copy_origin->fd = &connection->origin_fd;
    copy_origin->read_buffer = connection->write_buffer;
    copy_origin->write_buffer = connection->read_buffer;
    copy_origin->duplex = OP_READ | OP_WRITE; // TODO: Asignar dependiendo de las reglas de pop 3
    copy_origin->other = copy_client;
    copy_origin->target =ORIGIN;

    copy_filter->read_buffer = connection->filter_buffer;
    copy_filter->write_buffer = connection->write_buffer;
    copy_filter->duplex = OP_READ | OP_WRITE; // TODO: Asignar dependiendo de las reglas de pop 3
    copy_filter->other = NULL;
    copy_filter->target = FILTER;

    connection->filter.state = FILTER_CLOSE;
    // filter_init(key);
}


void on_departure_copying(const unsigned state, struct selector_key *key)
{
    printf("ON DEPARTURE");
    connection_destroy(ATTACHMENT(key));
}

void shut_down_copy(struct copy *copy){
// apagar ese fd de lectura
        log(ERROR, "Readed 0 or error on client. Error: %s", strerror(errno));
        shutdown(*copy->fd, SHUT_RD);
        copy->duplex &= ~OP_READ; // le sacamos el interes de lectura
        if (*copy->other->fd != -1)
        {
            // apagar el otro para escritura
            shutdown(*copy->other->fd, SHUT_WR);
            copy->other->duplex &= ~OP_WRITE;
        }
}

unsigned read_and_process_client(struct selector_key *key,struct copy *copy){
    size_t max_size_to_read;
    ssize_t readed;
    buffer *buffer = copy->read_buffer;
    unsigned ret_value = COPYING;

    uint8_t *ptr = buffer_write_ptr(buffer, &max_size_to_read);

    readed = recv(key->fd, ptr, max_size_to_read, 0);
       
    if (readed > 0)
    {
         /// TODO: METER MANEJO DEL PARSER COMMANDS ACA
        buffer_write_adv(buffer, readed);
    }
    else
    {
        shut_down_copy(copy);
        // TODO: Ver si no se tendria que retornar a error y cerrar las conexiones que quedaron abiertas.
    }
    return ret_value;
}

unsigned read_and_process_origin(struct selector_key *key,struct copy *copy){
    connection * connection = ATTACHMENT(key);
    size_t max_size_to_read;
    ssize_t readed;
    buffer *buffer = copy->read_buffer;
    unsigned ret_value = COPYING;

    uint8_t *ptr = buffer_write_ptr(buffer, &max_size_to_read);

    readed = recv(key->fd, ptr, max_size_to_read, 0);
       
    if (readed > 0)
    {
         /// TODO: METER MANEJO DEL PARSER RESPONSE ACA
        buffer_write_adv(buffer, readed);
        if(connection->filter.state == FILTER_CLOSE){
            //TODO: con el parser computamos que tipo de response es, si es de interes para el filter lo ponemos en starting (solo el retr es de interes)
            //Por ahora activamos siempre el filter
            connection->filter.state = FILTER_START;
        }
    }
    else
    {
        shut_down_copy(copy);
        // TODO: Ver si no se tendria que retornar a error y cerrar las conexiones que quedaron abiertas.
    }

    return ret_value;
}


unsigned read_and_process_filter(struct selector_key *key,struct copy *copy){
    size_t max_size_to_read;
    ssize_t readed;
    buffer *buffer = copy->read_buffer;
    unsigned ret_value = COPYING;

    uint8_t *ptr = buffer_write_ptr(buffer, &max_size_to_read);

    readed = recv(key->fd, ptr, max_size_to_read, 0);
       
    if (readed > 0)
    {
        buffer_write_adv(buffer, readed);
    }
    else if( readed ==0)
    {
        log(DEBUG,"Filter close connection");
        //TODO: filter_close(key)
        shut_down_copy(copy);
    }

    return ret_value;
}

void filter_compute_interest(struct selector_key *key){
    fd_interest interest = OP_NOOP;
    struct filter_data *filter = &ATTACHMENT(key)->filter;
    struct copy *copy = &ATTACHMENT(key)->copy_filter;

    if(filter->state == FILTER_WORKING){
        if(buffer_can_read(copy->read_buffer)){
            interest = OP_WRITE;
            if(selector_set_interest(key->s,filter->read_pipe[1],OP_WRITE)!= SELECTOR_SUCCESS){
                log(ERROR,"Failed to set write interest to filter");
            }
        }
    }
    if(buffer_can_write(copy->write_buffer)){
        interest |= OP_READ;
         if(selector_set_interest(key->s,filter->read_pipe[1],OP_READ)!= SELECTOR_SUCCESS){
            log(ERROR,"Failed to set read interest to filter");
        }
    }
}

static void filter_close(struct selector_key *key){
    connection * connection = ATTACHMENT(key);
    struct filter_data * filter = &connection->filter;

    if(filter->slave_proc_pid >0){
        kill(filter->slave_proc_pid,SIGKILL);
    }else{
        return;
    }

    for(int i=0;i<2;i++){
        if(filter->read_pipe[i] > 0){
            selector_unregister_fd(key->s,filter->read_pipe[i]);
            close(filter->read_pipe[i]);
        }
        if(filter->write_pipe[i] > 0){
            selector_unregister_fd(key->s,filter->write_pipe[i]);
            close(filter->write_pipe[i]);
        }
    }
    memset(filter,0,sizeof(struct filter_data));
    connection->filter.state = FILTER_CLOSE;
}

static fd_interest client_compute_interest(struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    struct copy *copy = &connection->copy_client;
    
    bool writeFromOrigin = buffer_can_read(copy->write_buffer) && (connection->filter.state == FILTER_START ||connection->filter.state == FILTER_CLOSE); // Todavia no esta el filtro 

    bool writeFromFilter = buffer_can_read(connection->copy_filter.read_buffer) && (connection->filter.state == FILTER_WORKING ||connection->filter.state == FILTER_FINISHED_SENDING);

    fd_interest ret = OP_NOOP;
    if ((copy->duplex & OP_READ) && buffer_can_write(copy->read_buffer))
    {
        ret |= OP_READ;
    }
    if ((copy->duplex & OP_WRITE) && (writeFromFilter || writeFromOrigin))
    {
        ret |= OP_WRITE;
    }

    if (selector_set_interest(key->s, *copy->fd, ret) != SELECTOR_SUCCESS)
    {
        log(ERROR,"Failed to set interests to fd in copy_compute_interests");
        abort();// TODO: VER SI CORRESPONDE ABORTAR
    }

    return ret;
}

static fd_interest origin_compute_interest(struct selector_key *key)
{
    connection *connection = ATTACHMENT(key);
    struct copy *copy = &connection->copy_origin;

    fd_interest ret = OP_NOOP;
    if ((copy->duplex & OP_READ) && buffer_can_write(copy->read_buffer))
    {
        ret |= OP_READ;
    }
    if ((copy->duplex & OP_WRITE) && buffer_can_read(copy->write_buffer))
    {
        ret |= OP_WRITE;
    }

    if (selector_set_interest(key->s, *copy->fd, ret) != SELECTOR_SUCCESS)
    {
        log(ERROR,"Failed to set interests to fd in copy_compute_interests");
        abort();// TODO: VER SI CORRESPONDE ABORTAR
    }

    return ret;
}

void copy_compute_interests(struct selector_key *key){
    connection *connection = ATTACHMENT(key);
    struct filter_data *filter = &connection->filter;

    switch (filter->state)
    {
        case FILTER_START:
            if(filter->slave_proc_pid == -1){
                log(DEBUG,"FILTER INIT");
                filter_init(key);
            }
            if(buffer_can_read(connection->copy_filter.read_buffer)){
                filter->state = FILTER_WORKING;
                filter_compute_interest(key);
            }
            break;
        
        case FILTER_FINISHED_SENDING:
            if(filter->read_pipe[1] != -1){
                selector_unregister_fd(key->s,filter->read_pipe[1]);
                close(filter->read_pipe[1]);
                filter->read_pipe[1] = -1;
            }
        case FILTER_ENDING:
            filter_close(key);

        case FILTER_WORKING:
            filter_compute_interest(key);
        default:
         break;
    }

    client_compute_interest(key);
    origin_compute_interest(key);
}


// Habria que hacer el manejo de dessetear el FD
unsigned on_read_ready_copying(struct selector_key *key)
{
    struct copy *copy = copy_ptr(key);
    unsigned ret_value = COPYING;

    switch (copy->target)
    {
    case CLIENT:
        read_and_process_client(key,copy);
        break;
    
    case ORIGIN:
        read_and_process_origin(key,copy);
        break;

    case FILTER:
        read_and_process_filter(key,copy);
        break;

    }

    copy_compute_interests(key);

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
    // if(copy->target == CLIENT){
    // log(DEBUG,"BORRAR SEND 1")
    // }else{
    //         log(DEBUG,"BORRAR SEND 2")

    // }
    sended = send(key->fd, ptr, max_size_to_write, MSG_NOSIGNAL);
            //write(ATTACHMENT(key)->filter.read_pipe[1],ptr,max_size_to_write);
    if (sended <= 0)
    {
        // apagar ese fd de escritura
        log(DEBUG, "Sended 0 or error.");
        shutdown(*copy->fd, SHUT_WR);
        copy->duplex &= ~OP_WRITE; // le sacamos el interes de escritura
        if (*copy->other->fd != -1)
        {
            // apagar el otro para lectura
            //  shutdown(*copy->other->fd,SHUT_RD);
            copy->other->duplex &= ~OP_READ;
        }
    }
    else
    {
        buffer_read_adv(buffer, sended);
    }

    copy_compute_interests(key);

    if (copy->duplex == OP_NOOP)
    {
        ret_value = DONE;
    }

    return ret_value;
}

///////////////////// ERROR CON MSG  ////////////////////////////////////////

static unsigned send_err_msg(struct selector_key *key) {
    connection * connection = ATTACHMENT(key);
    unsigned ret_val = ERROR_W_MESSAGE_ST;

    if(connection->error_data.err_msg == NULL)
        return ERROR_ST;
    if(connection->error_data.msg_len == 0)
        connection->error_data.msg_len = strlen(connection->error_data.err_msg);

    log(DEBUG,"Sending error to client: %s", connection->error_data.err_msg);
    char *   msg_ptr = connection->error_data.err_msg + connection->error_data.msg_sent_size;
    ssize_t  size_to_send = connection->error_data.msg_len - connection->error_data.msg_sent_size;
    ssize_t  n = send(connection->client_fd, msg_ptr, size_to_send, MSG_NOSIGNAL);
    // End states (error sending message or message complete)

    if(n == -1) {
        shutdown(connection->client_fd, SHUT_WR);
        ret_val = ERROR_ST;
    } else {
        connection->error_data.msg_sent_size += n;
        if(connection->error_data.msg_sent_size == connection->error_data.msg_len)
            return ERROR_ST;
    }
    // Else, continue sending
    return ret_val;
}
