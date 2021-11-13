#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "./include/sap.h"
#include "../utils/include/logger.h"
#include "../utils/include/selector.h"



sap_response response;
sap_request  request;

void manager_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer_in[1024], buffer_out[1024];
    int out_len = 0;
    //Limpiamos buffers
    memset(buffer_in, 0, 1024);
    memset(buffer_out, 0, 1024);


    ssize_t n = recvfrom(key->fd, buffer_in, 1024, 0, (struct sockaddr *)&client_addr, &client_addr_len);
    if (n <= 0)
    {
        log(ERROR, "recvfrom() failed: %s ", strerror(errno));
    }

    if (sap_buffer_to_request(buffer_in, &request) < 0){
        log(ERROR,"Error converting buffer to request");
    }

    log(DEBUG, "Version: %d\nop_code: %d\nauth_id:%d\nreq_id:%d ",
        request.v_type, request.op_code, request.auth_id, request.req_id);


    response.op_code = request.op_code;
    response.v_type = SAP_V_1_0_0;
    response.req_id = request.req_id;
    response.status_code = SC_OK;
    memcpy(response.data.string,"hola",5);


    if (sap_response_to_buffer(buffer_out,&response,&out_len) < 0) {
        log(ERROR, "Error converting response to buffer");
    }

    // Enviamos respuesta (el sendto no bloquea)
    sendto(key->fd, buffer_out, out_len, 0, (const struct sockaddr *)&client_addr, client_addr_len);

    log(DEBUG, "UDP sent:%s", buffer_out);

}