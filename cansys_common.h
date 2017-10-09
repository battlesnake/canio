#include <endian.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include "cansys.h"

/* Function+macro for printing hex dump */

#define cansys_printx(...)
//#define cansys_printx cansys_printx_real

static __attribute__((unused)) void cansys_printx_real(const char *name, const void *buf, size_t len)
{
	/* TODO remove/disable */
	const char *p = buf;
	printf("%s:", name);
	while (len--) {
		printf(" %02hhx", *p++);
	}
	printf("\n");
}

/*
 * Functions for reading/writing integers as little-endian, with no trailing
 * zero-bytes
 */

static __attribute__((unused)) uint64_t get_raw64(const void *buf, size_t buflen)
{
	uint64_t raw = 0;
	if (buflen > sizeof(raw)) {
		buflen = sizeof(raw);
	}
	memcpy(&raw, buf, buflen);
	return le64toh(raw);
}

static __attribute__((unused)) ssize_t set_raw64(void *buf, size_t buflen, uint64_t val)
{
	uint64_t raw = htole64(val);
	const uint8_t *raw_b = (void *) &raw;
	size_t retlen = sizeof(raw);
	while (retlen > 1 && raw_b[retlen - 1] == 0) {
		retlen--;
	}
	if (retlen > buflen) {
		errno = ERANGE;
		return -1;
	}
	if (retlen == 0) {
		retlen = 1;
	}
	memcpy(buf, &raw, buflen < sizeof(raw) ? buflen : raw);
	return retlen;
}

static __attribute__((unused)) uint64_t get_val64(const struct cansys_data *buf, size_t datalen)
{
	return get_raw64(buf->data, datalen);
}

static __attribute__((unused)) ssize_t set_val64(struct cansys_data *buf, uint64_t val)
{
	return set_raw64(buf->data, sizeof(buf->data), val);
}
