#include "include/manager_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../manager/include/sap.h"
#include "../utils/include/logger.h"
#include "../include/args.h"

#define MAXLINE 1024

// For Mac OS
#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

extern struct pop3_proxy_args pop3_proxy_args;

sap_response response;
sap_request  request;


int main() {
    int sockfd;
    struct sockaddr_in     servaddr;
    char* buffer;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(pop3_proxy_args.mng_port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    request.op_code = OP_STATS;
    request.req_id = 1;
    request.auth_id = 42;
    request.v_type = SAP_V_1_0_0;

    int n;
    socklen_t len;

    buffer = sap_request_to_buffer(&request,&n);

    sendto(sockfd, buffer, n,
           MSG_CONFIRM, (const struct sockaddr *) &servaddr,
           sizeof(servaddr));

    log(DEBUG,"Hello message sent.\n");

    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                 MSG_WAITALL, (struct sockaddr *) &servaddr,
                 &len);
    buffer[n] = '\0';
    printf("Server : %s\n", buffer);

    close(sockfd);
    free(buffer);
    return 0;
}