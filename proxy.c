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
#include "./utils/include/logger.h"
#include "./include/proxy.h"

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))

#define TRUE 1
#define FALSE 0
#define DEFAULT_SERVER_PORT 8888
#define DEFAULT_ORIGIN_PORT 110
#define MAX_SOCKETS 30
#define BUFFSIZE 1024
#define MAX_PENDING_CONNECTIONS 3 // un valor bajo, para realizar pruebas

enum IP_TYPE
{
    IPV4,
    IPV6
};

int main(int argc, char *argv[])
{
    int socket_to_client;
    int new_socket, client_socket[MAX_SOCKETS], max_clients = MAX_SOCKETS, activity, i, sd, origin_port, origin_addr;
    long valread;
    int max_sd;

    if (argc < 3)
    {
        log(FATAL, "Parameters invalid");
        return -1;
    }

    origin_addr = argv[2];
    origin_port = atoi(argv[1]);

    printf(origin_addr);
    printf("%d", origin_port);

    struct sockaddr_storage client_address; // Client address
    socklen_t client_address_len = sizeof(client_address);

    char buffer[BUFFSIZE + 1]; //data buffer of 1K

    //set of socket descriptors
    fd_set readfds;

    // Agregamos un buffer de escritura asociado a cada socket, para no bloquear por escritura
    // struct buffer bufferWrite[MAX_SOCKETS];
    // memset(bufferWrite, 0, sizeof bufferWrite);

    // y tambien los flags para writes
    fd_set writefds;

    // socket para IPv4 y para IPv6 (si estan disponibles)
    ///////////////////////////////////////////////////////////// IPv4
    // socket_to_client = buildSocketForClient(IPV4);
    // socket_to_client = buildSocketForClient(IPV6);
}

int buildSocketForClient(enum IP_TYPE ip_type)
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

    //set master socket to allow multiple connections , this is just a good habit, it will work without this
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