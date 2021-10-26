#ifndef PROXYPOP3NIO
#define PROXYPOP3NIO

#define TRUE 1
#define FALSE 0

#include "../../utils/include/netutils.h"

int proxy_passive_accept(struct selector_key *key);
void connection_pool_destroy();
unsigned on_read_ready_copying(struct selector_key *key);

#endif