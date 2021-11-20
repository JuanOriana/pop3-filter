#ifndef POP3FILTER_MANAGER_SERVER_H
#define POP3FILTER_MANAGER_SERVER_H

#include "../../utils/include/selector.h"

/**
 * Accept pasivo para el main
 * @param key la key del selector
 */
void manager_passive_accept(struct selector_key *key);

#endif //POP3FILTER_MANAGER_SERVER_H
