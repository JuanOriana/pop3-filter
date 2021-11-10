#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "include/sap.h"
#include "../utils/include/logger.h"
#include "../utils/include/selector.h"



void manager_passive_accept(struct selector_key *key)
{
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer_in[1024], *buffer_out;
    int out_len = 0;
    //Limpiamos buffer
    memset(buffer_in, 0, 1024);

    ssize_t n = recvfrom(key->fd, buffer_in, 1024, 0, (struct sockaddr *)&client_addr, &client_addr_len);
    if (n <= 0)
    {
        log(ERROR, "recvfrom() failed: %s ", strerror(errno));
    }

    sap_request* request = sap_buffer_to_request(buffer_in);

    log(DEBUG, "Version: %d\nop_code: %d\nauth_id:%d\nreq_id:%d ",
        request->v_type, request->op_code, request->auth_id, request->req_id);

    sap_data_type data;
    data.string=0;
    sap_response* response = create_new_sap_response(SAP_V_1_0_0,SC_OK,request->req_id,data);
    buffer_out = sap_response_to_buffer(response,&out_len);
    // Enviamos respuesta (el sendto no bloquea)
    sendto(socket, buffer_out, out_len, 0, (const struct sockaddr *)&client_addr, client_addr_len);

    log(DEBUG, "UDP sent:%s", buffer_out);

    free_sap_request(request);
    free_sap_response(response);
    free(buffer_out);
}