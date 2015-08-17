#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lib.h"
#include "../compat/include/uapi/linux/sclp.h"


int main(int argc, char **argv)
{
    int sock;
    int ret;
    uint16_t port;
    socklen_t sa_len;
    char buf[65535];
    struct sockaddr_in svr_sa;
    struct sockaddr_in clt_sa;

    if (argc != 2) {
	fprintf(stderr, "Usage: %s <port>\n", argv[0]);
	return -1;
    }
    
    /* Server port */
    if (! str_to_port(argv[1], &port)) {
	fprintf(stderr, "Invalid port : %s\n", argv[1]);
	return -1;
    }

    /* Create a socket descriptor for client acception */
    sock = socket(AF_INET, SOCK_SCLP, 0);
    if (sock < 0) {
	perror("socket");
	return -1;
    }

    memset(&svr_sa, 0, sizeof(svr_sa));
    svr_sa.sin_family = AF_INET;
    svr_sa.sin_port   = htons(port);
    svr_sa.sin_addr.s_addr = htonl(INADDR_ANY); /* Accept from any client */

    /* Bind local address and port to the socket descriptor */
    ret = bind(sock, (struct sockaddr*)&svr_sa, sizeof(svr_sa));
    if (ret < 0) {
	perror("bind");
	close(sock);
	return -1;
    }

    for (;;) {
	memset(&clt_sa, 0, sizeof(clt_sa));
	sa_len = sizeof(clt_sa);

	/* Receive data from the client */
	ret = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&clt_sa, &sa_len);
	if (ret < 0) {
	    perror("recvfrom");
	    close(sock);
	    return -1;
	} else if (ret == 0) {
	    fprintf(stderr, "Connection closed by the peer\n");
	    break;
	}

	printf("Received %d (%d) bytes\n", ret, (ret + 20 + sizeof(struct sclphdr)));
    }

    close(sock);

    return 0;
}
