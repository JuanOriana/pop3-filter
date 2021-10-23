#ifndef PROXYPOP3NIO
#define PROXYPOP3NIO

#define TRUE 1
#define FALSE 0
#define MAX_PENDING_CONNECTIONS 3

struct connection
{
    int fd_client;
    int fd_origin;
  
    struct state_machine stm;

    buffer client_buffer;
    buffer origin_buffer;
};


int proxy_create_connection(struct selector_key *key);
static int build_passive(IP_TYPE ip_type);
#endif