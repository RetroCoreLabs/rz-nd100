/*
 * iodevs.h - ND-100 I/O device register lookup
 */

#ifndef IODEVS_H
#define IODEVS_H

struct iox_device {
	int address;            /* IOX address (octal) */
	const char *device;     /* device prefix (e.g. "FLP1", "CON") */
	const char *regname;    /* register name */
	const char *direction;  /* "Read", "Write", or "Write/Read" */
	const char *bits;       /* bit field summary */
};

/*
 * Look up an IOX address. Returns pointer to device entry, or NULL.
 */
const struct iox_device *iox_lookup(int addr);

#endif /* IODEVS_H */
