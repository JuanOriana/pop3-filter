#ifndef PROXYPOP3NIO
#define PROXYPOP3NIO

#define TRUE 1
#define FALSE 0

#include "../../utils/include/netutils.h"

int proxy_create_connection(struct selector_key *key);
#endif