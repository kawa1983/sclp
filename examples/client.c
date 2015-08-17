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


int main(int argc, char ** argv)
{
    int sock;
    int ret;
    uint16_t port;
    size_t len;
    char *addr;
    char buf[128];
    struct sockaddr_in sa;

    if (argc != 3) {
	fprintf(stderr, "Usage: %s <address> <port>\n", argv[0]);
	return -1;
    }

    /* Server address */
    addr = argv[1];

    /* Server port */
    if (! str_to_port(argv[2], &port)) {
	fprintf(stderr, "Invalid port : %s\n", argv[2]);
	return -1;
    }

    /* Create a socket descriptor */
    sock = socket(AF_INET, SOCK_SCLP, 0);
    if (sock < 0) {
	perror("socket");
	return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port); /* Set server port */

    /* Translate address string to binary */
    ret = inet_pton(AF_INET, addr, &sa.sin_addr.s_addr);
    if (ret <= 0) {
	perror("inet_pton");
	close(sock);
	return -1;
    }

    printf("Input packet size\n");
    for (;;) {
	char *payload;
	size_t payload_len;
	int i;

	printf("> ");

	if (fgets(buf, sizeof(buf) - 1, stdin) == NULL) {
	    break;
	}

	len = strtol(buf, NULL, 10);
	if (len < 50 || 65535 < len) {
	    fprintf(stderr, "Invalid size\n");
	    continue;
	}

	payload_len = len - 20 - sizeof(struct sclphdr);

	payload = (char*)malloc(payload_len);
	if (! payload) {
	    fprintf(stderr, "Memory error\n");
	    close(sock);
	    return -1;
	}

	for (i = 0; i < payload_len; i++) {
	    payload[i] = i % 256;
	}

	/* Send input data to the server */
	ret = sendto(sock, payload, payload_len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
	    perror("sendto");
	    free(payload);
	    close(sock);
	    return -1;
	} 

	free(payload);
    }

    sendto(sock, buf, 0, 0, (struct sockaddr*)&sa, sizeof(sa));

    close(sock);

    return 0;
}
