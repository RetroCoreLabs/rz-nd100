/*
 * moncalls.h - SINTRAN III MON call lookup
 */

#ifndef MONCALLS_H
#define MONCALLS_H

struct mon_call {
	int number;             /* MON call number (decimal) */
	const char *short_name; /* short mnemonic (e.g. "INBT", "OUTBT") */
	const char *name;       /* descriptive name (e.g. "InByte") */
};

/*
 * Look up a MON call number. Returns pointer to entry, or NULL.
 */
const struct mon_call *mon_lookup(int num);

#endif /* MONCALLS_H */
