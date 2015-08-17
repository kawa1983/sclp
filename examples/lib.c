#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "lib.h"

bool str_to_port(const char *str, uint16_t *port)
{
    long value;
    char *endptr;

    errno = 0;
    value = strtol(str, &endptr, 10);
    if (errno != 0 && (value == LONG_MAX || value == LONG_MIN || value == 0)) {
	perror("strtok");
	return false;
    } else if (str == endptr) {
	return false;
    } else if (value < 0 || 65535 < value) {
	return false;
    }
    *port = (uint16_t)value;
    return true;
}
