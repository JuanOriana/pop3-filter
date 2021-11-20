#ifndef PROXYPOP3NIO
#define PROXYPOP3NIO

#define TRUE 1
#define FALSE 0
#define TIMEOUT 200.0 // TODO: incremetnar este valor, valor bajo para probar

#include "../../utils/include/netutils.h"

/*
 * Funcion de manejo de accept para el proxy
 */
void proxy_passive_accept(struct selector_key *key);

/*
 * Destruye todas las instancias que hayan quedado sin uso en el pool
 */
void connection_pool_destroy();

#endif