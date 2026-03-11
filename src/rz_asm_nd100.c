/*
 * rz_asm_nd100.c - Rizin disassembler/assembler plugin for ND-100/ND-110
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "nd100_disasm.h"
#include "moncalls.h"
#include "iodevs.h"

/* ---- Assembler helpers ---- */

/* Parse a register name for skip/register operations.
 * Returns register index 0-7, or -1 on failure.
 * Names: 0/S, D, P/SP, B, L, A, T, X (matching skipregn_dst/src) */
static int parse_reg(const char *s) {
	if (!s || !*s) return -1;
	if (s[0] == '0' && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 0;
	if ((s[0] == 'S' || s[0] == 's') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 0;
	if ((s[0] == 'D' || s[0] == 'd') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 1;
	if ((s[0] == 'P' || s[0] == 'p') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 2;
	if (!rz_str_ncasecmp(s, "SP", 2) && (s[2] == '\0' || isspace((unsigned char)s[2]))) return 2;
	if ((s[0] == 'B' || s[0] == 'b') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 3;
	if ((s[0] == 'L' || s[0] == 'l') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 4;
	if ((s[0] == 'A' || s[0] == 'a') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 5;
	if ((s[0] == 'T' || s[0] == 't') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 6;
	if ((s[0] == 'X' || s[0] == 'x') && (s[1] == '\0' || isspace((unsigned char)s[1]))) return 7;
	return -1;
}

/* Parse D-prefixed register for skip dst: DD, DP, DB, DL, DA, DT, DX */
static int parse_dreg(const char *s) {
	if (!s || (s[0] != 'D' && s[0] != 'd')) return -1;
	switch (toupper((unsigned char)s[1])) {
	case 'D': case 'd': return 1;
	case 'P': case 'p': return 2;
	case 'B': case 'b': return 3;
	case 'L': case 'l': return 4;
	case 'A': case 'a': return 5;
	case 'T': case 't': return 6;
	case 'X': case 'x': return 7;
	}
	return -1;
}

/* Parse S-prefixed register for skip src: SD, SP, SB, SL, SA, ST, SX */
static int parse_sreg(const char *s) {
	if (!s || (s[0] != 'S' && s[0] != 's')) return -1;
	switch (toupper((unsigned char)s[1])) {
	case 'D': case 'd': return 1;
	case 'P': case 'p': return 2;
	case 'B': case 'b': return 3;
	case 'L': case 'l': return 4;
	case 'A': case 'a': return 5;
	case 'T': case 't': return 6;
	case 'X': case 'x': return 7;
	}
	return -1;
}

/* Parse a signed 8-bit octal or decimal number.
 * Supports: -17 (octal), 0x1F (hex), 31 (octal by default for ND-100).
 * The ND-100 disassembler outputs octal by default. */
static int parse_offset(const char *s, int *val) {
	char *end;
	int neg = 0;
	long v;

	if (!s) return -1;
	while (isspace((unsigned char)*s)) s++;
	if (*s == '-') { neg = 1; s++; }
	else if (*s == '+') { s++; }

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		v = strtol(s, &end, 16);
	} else {
		/* Default: octal (ND-100 convention) */
		v = strtol(s, &end, 8);
	}
	if (end == s) return -1;
	if (neg) v = -v;
	*val = (int)v;
	return 0;
}

/* Parse addressing mode: returns relmode 0-7 and advances *rest past mode tokens.
 * Input is the operand string after the mnemonic.
 *
 * Supports two syntax styles:
 *   Rizin disasm:  "LDA ,B 10"  "LDA I ,B ,X 5"  (mode before offset)
 *   nd100-as:      "LDA -4,B"   "LDA 17,B,X"     (mode after offset)
 *   nd100-as:      "LDA ,X I ,B 4"                (mixed)
 *
 * Modes: "" (0), ",B" (1), "I" (2), "I ,B" (3), ",X" (4), ",X ,B" (5),
 *        "I ,X" (6), "I ,B ,X" (7) */
static int parse_addrmode(const char **rest) {
	const char *s = *rest;
	int indirect = 0, breg = 0, xreg = 0;

	while (isspace((unsigned char)*s)) s++;

	/* Check for ,X prefix (nd100-as mode 6/7: ",X I ...") */
	if (*s == ',') {
		const char *t = s + 1;
		while (isspace((unsigned char)*t)) t++;
		if (*t == 'X' || *t == 'x') {
			xreg = 1;
			s = t + 1;
			while (isspace((unsigned char)*s)) s++;
		} else if (*t == 'B' || *t == 'b') {
			breg = 1;
			s = t + 1;
			while (isspace((unsigned char)*s)) s++;
		}
	}

	/* Check for I (indirect) prefix */
	if ((*s == 'I' || *s == 'i') && (s[1] == ' ' || s[1] == '\t' || s[1] == ',')) {
		indirect = 1;
		s++;
		while (isspace((unsigned char)*s)) s++;
	}

	/* Check for ,B and ,X tokens */
	while (*s == ',') {
		const char *t = s + 1;
		while (isspace((unsigned char)*t)) t++;
		if (*t == 'B' || *t == 'b') {
			breg = 1;
			s = t + 1;
		} else if (*t == 'X' || *t == 'x') {
			xreg = 1;
			s = t + 1;
		} else {
			break;
		}
		while (isspace((unsigned char)*s)) s++;
	}

	*rest = s;
	return (indirect << 1) | breg | (xreg << 2);
}

/* Parse trailing addressing mode after offset: handles "LDA -4,B" syntax */
static int parse_trailing_addrmode(const char **rest) {
	const char *s = *rest;
	int breg = 0, xreg = 0;

	while (*s == ',') {
		s++;
		while (isspace((unsigned char)*s)) s++;
		if (*s == 'B' || *s == 'b') {
			breg = 1;
			s++;
		} else if (*s == 'X' || *s == 'x') {
			xreg = 1;
			s++;
		} else {
			break;
		}
		while (isspace((unsigned char)*s)) s++;
	}

	*rest = s;
	return breg | (xreg << 2);
}

/* Parse skip condition name, returns 0-7 or -1 */
static int parse_skipcond(const char *s) {
	if (!rz_str_ncasecmp(s, "EQL", 3)) return 0;
	if (!rz_str_ncasecmp(s, "GEQ", 3)) return 1;
	if (!rz_str_ncasecmp(s, "GRE", 3)) return 2;
	if (!rz_str_ncasecmp(s, "MGRE", 4)) return 3;
	if (!rz_str_ncasecmp(s, "UEQ", 3)) return 4;
	if (!rz_str_ncasecmp(s, "LSS", 3)) return 5;
	if (!rz_str_ncasecmp(s, "LST", 3)) return 6;
	if (!rz_str_ncasecmp(s, "MLST", 4)) return 7;
	return -1;
}

/* Encode a memory-reference instruction: top5 opcode | relmode | offset */
static uint16_t encode_memref(uint16_t opcode, int relmode, int offset) {
	return opcode | ((relmode & 0x07) << 8) | (offset & 0xFF);
}

/* Skip whitespace and return pointer */
static const char *skip_ws(const char *s) {
	while (isspace((unsigned char)*s)) s++;
	return s;
}

/* Parse status bit name for bit operations, returns 0-7 or -1 */
static int parse_stsbit(const char *s) {
	if (!s) return -1;
	if (!rz_str_ncasecmp(s, "SSPTM", 5) && (s[5] == '\0' || isspace((unsigned char)s[5]))) return 0;
	if (!rz_str_ncasecmp(s, "SSTG", 4) && (s[4] == '\0' || isspace((unsigned char)s[4]))) return 1;
	if (!rz_str_ncasecmp(s, "SSK", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 2;
	if (!rz_str_ncasecmp(s, "SSZ", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 3;
	if (!rz_str_ncasecmp(s, "SSQ", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 4;
	if (!rz_str_ncasecmp(s, "SSO", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 5;
	if (!rz_str_ncasecmp(s, "SSC", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 6;
	if (!rz_str_ncasecmp(s, "SSM", 3) && (s[3] == '\0' || isspace((unsigned char)s[3]))) return 7;
	return -1;
}

/* Parse bit operation condition: ZRO(0), ONE(1), BCM(2), BAC(3) */
static int parse_bitcond(const char *s) {
	if (!rz_str_ncasecmp(s, "ZRO", 3)) return 0;
	if (!rz_str_ncasecmp(s, "ONE", 3)) return 1;
	if (!rz_str_ncasecmp(s, "BCM", 3)) return 2;
	if (!rz_str_ncasecmp(s, "BAC", 3)) return 3;
	return -1;
}

/* Parse D-prefixed register for bit/IRW/IRR ops, including DS for index 0 */
static int parse_dreg_full(const char *s) {
	if (!s || (s[0] != 'D' && s[0] != 'd')) return -1;
	switch (toupper((unsigned char)s[1])) {
	case 'S': return 0;
	case 'D': return 1;
	case 'P': return 2;
	case 'B': return 3;
	case 'L': return 4;
	case 'A': return 5;
	case 'T': return 6;
	case 'X': return 7;
	}
	return -1;
}

/* Check if token matches (case-insensitive, delimited by space/null) */
static int tok_match(const char *s, const char *tok) {
	int len = (int)strlen(tok);
	if (rz_str_ncasecmp(s, tok, len) != 0) return 0;
	return (s[len] == '\0' || isspace((unsigned char)s[len]) ||
		s[len] == ',' || s[len] == ';');
}

static int assemble(RzAsm *a, RzAsmOp *op, const char *input) {
	char buf[256];
	const char *p;
	uint16_t word = 0;
	int offset_val;
	int relmode;
	int found = 0;
	ut8 outbuf[2];

	/* Copy input, strip leading whitespace and comments */
	rz_str_ncpy(buf, input, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
	{
		char *semi = strchr(buf, ';');
		if (semi) *semi = '\0';
		/* Trim trailing whitespace */
		int l = (int)strlen(buf);
		while (l > 0 && isspace((unsigned char)buf[l-1])) buf[--l] = '\0';
	}
	p = skip_ws(buf);
	if (!*p) return -1;

	/* ---- Simple fixed-word instructions ---- */
	if (tok_match(p, "EXIT")) {
		word = 0146142; found = 1;
	} else if (tok_match(p, "LEAVE")) {
		word = 0140136; found = 1;
	} else if (tok_match(p, "ELEAV")) {
		word = 0140137; found = 1;
	} else if (tok_match(p, "ENTR")) {
		word = 0140135; found = 1;
	} else if (tok_match(p, "INIT")) {
		word = 0140134; found = 1;
	} else if (tok_match(p, "OPCOM")) {
		word = 0150400; found = 1;
	} else if (tok_match(p, "IOF")) {
		word = 0150401; found = 1;
	} else if (tok_match(p, "ION")) {
		word = 0150402; found = 1;
	} else if (tok_match(p, "POF")) {
		word = 0150404; found = 1;
	} else if (tok_match(p, "PIOF")) {
		word = 0150405; found = 1;
	} else if (tok_match(p, "SEX")) {
		word = 0150406; found = 1;
	} else if (tok_match(p, "REX")) {
		word = 0150407; found = 1;
	} else if (tok_match(p, "PON")) {
		word = 0150410; found = 1;
	} else if (tok_match(p, "PION")) {
		word = 0150412; found = 1;
	} else if (tok_match(p, "IOXT")) {
		word = 0150415; found = 1;
	} else if (tok_match(p, "EXAM")) {
		word = 0150416; found = 1;
	} else if (tok_match(p, "DEPO")) {
		word = 0150417; found = 1;
	} else if (tok_match(p, "WAIT")) {
		word = 0151000; found = 1;
	} else if (tok_match(p, "ADDD")) {
		word = 0140120; found = 1;
	} else if (tok_match(p, "SUBD")) {
		word = 0140121; found = 1;
	} else if (tok_match(p, "COMD")) {
		word = 0140122; found = 1;
	} else if (tok_match(p, "TSET")) {
		word = 0140123; found = 1;
	} else if (tok_match(p, "PACK")) {
		word = 0140124; found = 1;
	} else if (tok_match(p, "UPACK")) {
		word = 0140125; found = 1;
	} else if (tok_match(p, "SHDE")) {
		word = 0140126; found = 1;
	} else if (tok_match(p, "RDUS")) {
		word = 0140127; found = 1;
	} else if (tok_match(p, "BFILL")) {
		word = 0140130; found = 1;
	} else if (tok_match(p, "MOVB")) {
		/* MOVB vs MOVBF */
		if (tok_match(p, "MOVBF")) {
			word = 0140132; found = 1;
		} else {
			word = 0140131; found = 1;
		}
	} else if (tok_match(p, "MOVBF")) {
		word = 0140132; found = 1;
	} else if (tok_match(p, "VERSN")) {
		word = 0140133; found = 1;
	} else if (tok_match(p, "LBYT")) {
		word = 0142200; found = 1;
	} else if (tok_match(p, "SBYT")) {
		word = 0142600; found = 1;
	} else if (tok_match(p, "GECO")) {
		word = 0142700; found = 1;
	} else if (tok_match(p, "MOVEW")) {
		word = 0143100; found = 1;
	} else if (tok_match(p, "LWCS")) {
		word = 0143500; found = 1;
	} else if (tok_match(p, "MIX3")) {
		word = 0143200; found = 1;
	} else if (tok_match(p, "HALT")) {
		word = 0140200; found = 1;
	} else if (tok_match(p, "SETPT")) {
		word = 0140300; found = 1;
	} else if (tok_match(p, "CLEPT")) {
		word = 0140301; found = 1;
	} else if (tok_match(p, "CLNREENT")) {
		word = 0140302; found = 1;
	} else if (tok_match(p, "CHREENT-PAGES")) {
		word = 0140303; found = 1;
	} else if (tok_match(p, "CLEPU")) {
		word = 0140304; found = 1;
	} else if (tok_match(p, "VERSN")) {
		word = 0140133; found = 1;
	/* Physical memory transfer instructions */
	} else if (tok_match(p, "LDATX")) {
		word = 0143300; found = 1;
	} else if (tok_match(p, "LDXTX")) {
		word = 0143301; found = 1;
	} else if (tok_match(p, "LDDTX")) {
		word = 0143302; found = 1;
	} else if (tok_match(p, "LDBTX")) {
		word = 0143303; found = 1;
	} else if (tok_match(p, "STATX")) {
		word = 0143304; found = 1;
	} else if (tok_match(p, "STZTX")) {
		word = 0143305; found = 1;
	} else if (tok_match(p, "STDTX")) {
		word = 0143306; found = 1;
	/* ND-110 specific instructions */
	} else if (tok_match(p, "WGLOB")) {
		word = 0140500; found = 1;
	} else if (tok_match(p, "RGLOB")) {
		word = 0140501; found = 1;
	} else if (tok_match(p, "INSPL")) {
		word = 0140502; found = 1;
	} else if (tok_match(p, "REMPL")) {
		word = 0140503; found = 1;
	} else if (tok_match(p, "CNREK")) {
		word = 0140504; found = 1;
	} else if (tok_match(p, "CLPT")) {
		word = 0140505; found = 1;
	} else if (tok_match(p, "ENPT")) {
		word = 0140506; found = 1;
	} else if (tok_match(p, "REPT")) {
		word = 0140507; found = 1;
	} else if (tok_match(p, "LBIT")) {
		word = 0140510; found = 1;
	} else if (tok_match(p, "SBITP")) {
		word = 0140513; found = 1;
	} else if (tok_match(p, "LBYTP")) {
		word = 0140514; found = 1;
	} else if (tok_match(p, "SBYTP")) {
		word = 0140515; found = 1;
	} else if (tok_match(p, "TSETP")) {
		word = 0140516; found = 1;
	} else if (tok_match(p, "RDUSP")) {
		word = 0140517; found = 1;
	}

	/* ---- Memory reference instructions ---- */
	if (!found) {
		/* Table of memory-reference mnemonics and their top-5-bit opcodes */
		static const struct { const char *name; uint16_t opcode; } memref[] = {
			{"STZ", 0000000}, {"STA", 0004000}, {"STT", 0010000},
			{"STX", 0014000}, {"STD", 0020000}, {"LDD", 0024000},
			{"STF", 0030000}, {"LDF", 0034000}, {"MIN", 0040000},
			{"LDA", 0044000}, {"LDT", 0050000}, {"LDX", 0054000},
			{"ADD", 0060000}, {"SUB", 0064000}, {"AND", 0070000},
			{"ORA", 0074000}, {"FAD", 0100000}, {"FSB", 0104000},
			{"FMU", 0110000}, {"FDV", 0114000}, {"MPY", 0120000},
			{"JMP", 0124000}, {"JPL", 0134000},
			{NULL, 0}
		};
		int i;
		for (i = 0; memref[i].name; i++) {
			int nlen = (int)strlen(memref[i].name);
			if (rz_str_ncasecmp(p, memref[i].name, nlen) == 0 &&
			    (p[nlen] == '\0' || isspace((unsigned char)p[nlen]))) {
				p = skip_ws(p + nlen);
				relmode = parse_addrmode(&p);
				p = skip_ws(p);
				if (parse_offset(p, &offset_val) == 0) {
					/* Advance past the parsed number */
					char *endp;
					if (p[0] == '-' || p[0] == '+') {
						strtol(p + 1, &endp, 8);
						endp = (endp == p + 1) ? (char *)p : endp;
					} else if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
						strtol(p, &endp, 16);
					} else {
						strtol(p, &endp, 8);
					}
					/* Check for trailing ,B or ,X (nd100-as syntax) */
					const char *trail = endp;
					int trail_mode = parse_trailing_addrmode(&trail);
					relmode |= trail_mode;
					word = encode_memref(memref[i].opcode, relmode, offset_val);
					found = 1;
				} else if (*p == '\0') {
					/* No offset: default to 0 */
					word = encode_memref(memref[i].opcode, relmode, 0);
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- Conditional branches (JAP/JAN/JAZ/JAF/JPC/JNC/JXZ/JXN) ---- */
	if (!found) {
		static const struct { const char *name; uint16_t opcode; } cbr[] = {
			{"JAP", 0130000}, {"JAN", 0130400}, {"JAZ", 0131000},
			{"JAF", 0131400}, {"JPC", 0132000}, {"JNC", 0132400},
			{"JXZ", 0133000}, {"JXN", 0133400},
			{NULL, 0}
		};
		int i;
		for (i = 0; cbr[i].name; i++) {
			int nlen = (int)strlen(cbr[i].name);
			if (rz_str_ncasecmp(p, cbr[i].name, nlen) == 0 &&
			    (p[nlen] == '\0' || isspace((unsigned char)p[nlen]))) {
				p = skip_ws(p + nlen);
				if (parse_offset(p, &offset_val) == 0) {
					word = cbr[i].opcode | (offset_val & 0xFF);
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- Argument instructions (SAB/SAA/SAT/SAX/AAB/AAA/AAT/AAX) ---- */
	if (!found) {
		static const struct { const char *name; uint16_t opcode; } arg[] = {
			{"SAB", 0170000}, {"SAA", 0170400}, {"SAT", 0171000},
			{"SAX", 0171400}, {"AAB", 0172000}, {"AAA", 0172400},
			{"AAT", 0173000}, {"AAX", 0173400},
			{NULL, 0}
		};
		int i;
		for (i = 0; arg[i].name; i++) {
			int nlen = (int)strlen(arg[i].name);
			if (rz_str_ncasecmp(p, arg[i].name, nlen) == 0 &&
			    (p[nlen] == '\0' || isspace((unsigned char)p[nlen]))) {
				p = skip_ws(p + nlen);
				if (parse_offset(p, &offset_val) == 0) {
					word = arg[i].opcode | (offset_val & 0xFF);
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- MON <number> ---- */
	if (!found && tok_match(p, "MON")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0153000 | (offset_val & 0xFF);
			found = 1;
		}
	}

	/* ---- IOX <address> ---- */
	if (!found && tok_match(p, "IOX")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0164000 | (offset_val & 0x7FF);
			found = 1;
		}
	}

	/* ---- IOT <address> ---- */
	if (!found && tok_match(p, "IOT")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0160000 | (offset_val & 0x7FF);
			found = 1;
		}
	}

	/* ---- IDENT PL10/PL11/PL12/PL13 ---- */
	if (!found && tok_match(p, "IDENT")) {
		p = skip_ws(p + 5);
		if (tok_match(p, "PL10")) {
			word = 0143604; found = 1;
		} else if (tok_match(p, "PL11")) {
			word = 0143611; found = 1;
		} else if (tok_match(p, "PL12")) {
			word = 0143622; found = 1;
		} else if (tok_match(p, "PL13")) {
			word = 0143643; found = 1;
		}
	}

	/* ---- EXR <src_reg> ---- */
	if (!found && tok_match(p, "EXR")) {
		p = skip_ws(p + 3);
		int src = parse_sreg(p);
		if (src < 0) src = parse_reg(p);
		if (src >= 0) {
			word = 0140600 | (src << 3);
			found = 1;
		}
	}

	/* ---- NLZ <offset> ---- */
	if (!found && tok_match(p, "NLZ")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0151400 | (offset_val & 0xFF);
			found = 1;
		}
	}

	/* ---- DNZ <offset> ---- */
	if (!found && tok_match(p, "DNZ")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0152000 | (offset_val & 0xFF);
			found = 1;
		}
	}

	/* ---- IRW <level> <Dreg> ---- */
	if (!found && tok_match(p, "IRW")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			char *endp;
			strtol(p, &endp, 8);
			p = skip_ws(endp);
			int reg = parse_dreg_full(p);
			if (reg >= 0) {
				word = 0153400 | (offset_val & 0x78) | (reg & 0x07);
				found = 1;
			}
		}
	}

	/* ---- IRR <level> <Dreg> ---- */
	if (!found && tok_match(p, "IRR")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			char *endp;
			strtol(p, &endp, 8);
			p = skip_ws(endp);
			int reg = parse_dreg_full(p);
			if (reg >= 0) {
				word = 0153600 | (offset_val & 0x78) | (reg & 0x07);
				found = 1;
			}
		}
	}

	/* ---- ND-110 LASB/SASB/LACB/SACB/LXSB/LXCB/SZSB/SZCB <delta> ---- */
	if (!found) {
		static const struct { const char *name; int nlen; uint16_t base; } nd110_delta[] = {
			{"LASB", 4, 0140700}, {"SASB", 4, 0140701},
			{"LACB", 4, 0140702}, {"SACB", 4, 0140703},
			{"LXSB", 4, 0140704}, {"LXCB", 4, 0140705},
			{"SZSB", 4, 0140706}, {"SZCB", 4, 0140707},
			{NULL, 0, 0}
		};
		int i;
		for (i = 0; nd110_delta[i].name; i++) {
			if (tok_match(p, nd110_delta[i].name)) {
				p = skip_ws(p + nd110_delta[i].nlen);
				if (parse_offset(p, &offset_val) == 0) {
					word = nd110_delta[i].base | (offset_val & 0x38);
					found = 1;
				} else {
					/* No argument = delta 0 */
					word = nd110_delta[i].base;
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- SKP IF <dst> <cond> <src> ---- */
	if (!found && tok_match(p, "SKP")) {
		p = skip_ws(p + 3);
		if (tok_match(p, "IF")) {
			p = skip_ws(p + 2);
			int dst, src, cond;
			/* Parse destination register (D-prefixed: DA, DT, etc. or "0") */
			if (*p == '0' && (p[1] == '\0' || isspace((unsigned char)p[1]))) {
				dst = 0;
				p = skip_ws(p + 1);
			} else {
				dst = parse_dreg(p);
				if (dst >= 0) {
					while (*p && !isspace((unsigned char)*p)) p++;
					p = skip_ws(p);
				}
			}
			/* Parse condition */
			cond = parse_skipcond(p);
			if (cond >= 0) {
				while (*p && !isspace((unsigned char)*p)) p++;
				p = skip_ws(p);
			}
			/* Parse source register (S-prefixed: SA, ST, etc. or "0") */
			if (*p == '0' && (p[1] == '\0' || isspace((unsigned char)p[1]))) {
				src = 0;
			} else {
				src = parse_sreg(p);
			}
			if (dst >= 0 && cond >= 0 && src >= 0) {
				word = 0140000 | (cond << 8) | (src << 3) | dst;
				found = 1;
			}
		}
	}

	/* ---- Register operations: RADD, SWAP, RAND, REXO, RORA, RSUB ---- */
	if (!found) {
		static const struct { const char *name; int nlen; uint16_t base; } regops[] = {
			{"RADD", 4, 0146000},
			{"SWAP", 4, 0144000},
			{"RAND", 4, 0144400},
			{"REXO", 4, 0145000},
			{"RORA", 4, 0145400},
			{"RSUB", 4, 0146600},
			{NULL, 0, 0}
		};
		int i;
		for (i = 0; regops[i].name; i++) {
			if (tok_match(p, regops[i].name)) {
				uint16_t base = regops[i].base;
				p = skip_ws(p + regops[i].nlen);

				/* Parse optional modifier flags: CLD, CM1, AD1, ADC */
				uint16_t mod = 0;
				for (;;) {
					if (tok_match(p, "CLD")) {
						mod |= 0100;
						p = skip_ws(p + 3);
					} else if (tok_match(p, "CM1")) {
						mod |= 0200;
						p = skip_ws(p + 3);
					} else if (tok_match(p, "AD1")) {
						mod |= 0400;
						p = skip_ws(p + 3);
					} else if (tok_match(p, "ADC")) {
						mod |= 01000;
						p = skip_ws(p + 3);
					} else {
						break;
					}
				}

				/* Parse source register (S-prefixed: SA, ST, etc.) */
				int src = -1, dst = -1;
				src = parse_sreg(p);
				if (src < 0) src = parse_reg(p);
				if (src >= 0) {
					while (*p && !isspace((unsigned char)*p)) p++;
					p = skip_ws(p);
				}
				/* Parse destination register (D-prefixed: DA, DT, etc.) */
				dst = parse_dreg(p);
				if (dst < 0) dst = parse_reg(p);

				if (src >= 0 && dst >= 0) {
					word = base + mod + (src << 3) + dst;
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- RCLR <Dreg> = RADD CLD 0 <Dreg> ---- */
	if (!found && tok_match(p, "RCLR")) {
		p = skip_ws(p + 4);
		int dst = parse_dreg(p);
		if (dst < 0) dst = parse_reg(p);
		if (dst >= 0) {
			word = 0146100 + dst;  /* RADD CLD S0 Ddst */
			found = 1;
		}
	}

	/* ---- RINC <Dreg> = RADD AD1 0 <Dreg> ---- */
	if (!found && tok_match(p, "RINC")) {
		p = skip_ws(p + 4);
		int dst = parse_dreg(p);
		if (dst < 0) dst = parse_reg(p);
		if (dst >= 0) {
			word = 0146400 + dst;  /* RADD AD1 S0 Ddst */
			found = 1;
		}
	}

	/* ---- RDCR <Dreg> = RADD CM1 0 <Dreg> ---- */
	if (!found && tok_match(p, "RDCR")) {
		p = skip_ws(p + 4);
		int dst = parse_dreg(p);
		if (dst < 0) dst = parse_reg(p);
		if (dst >= 0) {
			word = 0146200 + dst;  /* RADD CM1 S0 Ddst */
			found = 1;
		}
	}

	/* ---- COPY shorthand: COPY SL DA = RADD CLD SA DL ---- */
	if (!found && tok_match(p, "COPY")) {
		p = skip_ws(p + 4);
		int src = -1, dst = -1;
		if (*p == 'S' || *p == 's') {
			src = parse_sreg(p);
			while (*p && !isspace((unsigned char)*p)) p++;
			p = skip_ws(p);
		}
		if (*p == 'D' || *p == 'd') {
			dst = parse_dreg(p);
		}
		if (src >= 0 && dst >= 0) {
			/* COPY = RADD CLD (0146100) */
			word = 0146100 + (src << 3) + dst;
			found = 1;
		}
	}

	/* ---- RMPY <src> <dst> ---- */
	if (!found && tok_match(p, "RMPY")) {
		p = skip_ws(p + 4);
		int src = -1, dst = -1;
		src = parse_sreg(p);
		if (src < 0) src = parse_reg(p);
		if (src >= 0) {
			while (*p && !isspace((unsigned char)*p)) p++;
			p = skip_ws(p);
		}
		dst = parse_dreg(p);
		if (dst < 0) dst = parse_reg(p);
		if (src >= 0 && dst >= 0) {
			word = 0141200 + (src << 3) + dst;
			found = 1;
		}
	}

	/* ---- RDIV <src> ---- */
	if (!found && tok_match(p, "RDIV")) {
		p = skip_ws(p + 4);
		int src = parse_sreg(p);
		if (src < 0) src = parse_reg(p);
		if (src >= 0) {
			word = 0141600 + (src << 3);
			found = 1;
		}
	}

	/* ---- SHT/SHA/SHD/SAD <shtype> <count> ---- */
	if (!found) {
		static const struct { const char *name; uint16_t base; } shifts[] = {
			{"SHT", 0154000}, {"SHD", 0154200},
			{"SHA", 0154400}, {"SAD", 0154600},
			{NULL, 0}
		};
		int i;
		for (i = 0; shifts[i].name; i++) {
			if (tok_match(p, shifts[i].name)) {
				p = skip_ws(p + 3);
				uint16_t shtype = 0;
				if (tok_match(p, "ROT")) { shtype = 1; p = skip_ws(p + 3); }
				else if (tok_match(p, "ZIN")) { shtype = 2; p = skip_ws(p + 3); }
				else if (tok_match(p, "LIN")) { shtype = 3; p = skip_ws(p + 3); }

				/* Check for SHR (shift right indicator) */
				int is_right = 0;
				if (tok_match(p, "SHR")) {
					is_right = 1;
					p = skip_ws(p + 3);
				}

				if (parse_offset(p, &offset_val) == 0) {
					int count;
					if (is_right) {
						count = (-offset_val) & 0x3F;
					} else {
						count = offset_val & 0x3F;
					}
					word = shifts[i].base | (shtype << 9) | count;
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- TRA/TRR/MCL/MST <intreg> ---- */
	if (!found) {
		static const struct { const char *name; uint16_t base; } intops[] = {
			{"TRA", 0150000}, {"TRR", 0150100},
			{"MCL", 0150200}, {"MST", 0150300},
			{NULL, 0}
		};
		int i;
		for (i = 0; intops[i].name; i++) {
			if (tok_match(p, intops[i].name)) {
				p = skip_ws(p + 3);
				/* Parse internal register name or number */
				static const char *ir_r[] = {
					"PANS","STS","OPR","PGS","PVL","IIC","PID","PIE",
					"CSR","ACTL","ALD","PES","PGC","PEA",NULL
				};
				static const char *ir_w[] = {
					"PANC","STS","LMP","PCR",NULL,
					"IIE","PID","PIE","CCL","LCIL","UCILR",NULL
				};
				const char **table = (intops[i].base == 0150000) ? ir_r : ir_w;
				int j, reg_num = -1;
				for (j = 0; j < 16 && table[j]; j++) {
					if (table[j] && tok_match(p, table[j])) {
						reg_num = j;
						break;
					}
				}
				if (reg_num < 0) {
					/* Try numeric */
					if (parse_offset(p, &offset_val) == 0) {
						reg_num = offset_val & 0x0F;
					}
				}
				if (reg_num >= 0) {
					word = intops[i].base | (reg_num & 0x0F);
					found = 1;
				}
				break;
			}
		}
	}

	/* ---- SRB <bits> ---- */
	if (!found && tok_match(p, "SRB")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0152400 | (offset_val & 0x78);
			found = 1;
		}
	}

	/* ---- LRB <bits> ---- */
	if (!found && tok_match(p, "LRB")) {
		p = skip_ws(p + 3);
		if (parse_offset(p, &offset_val) == 0) {
			word = 0152600 | ((offset_val & 0x0F) << 3);
			found = 1;
		}
	}

	/* ---- ROP NOOP ---- */
	if (!found && tok_match(p, "ROP")) {
		p = skip_ws(p + 3);
		if (tok_match(p, "NOOP")) {
			word = 0147700;
			found = 1;
		}
	}

	/* ---- BSET/BSKP with condition: BSET ZRO <args>, BSKP ONE <args> ---- */
	if (!found) {
		static const struct { const char *name; int nlen; uint16_t base; } bsetskp[] = {
			{"BSET", 4, 0174000},
			{"BSKP", 4, 0175000},
			{NULL, 0, 0}
		};
		int i;
		for (i = 0; bsetskp[i].name; i++) {
			if (tok_match(p, bsetskp[i].name)) {
				p = skip_ws(p + bsetskp[i].nlen);
				int cond = parse_bitcond(p);
				if (cond >= 0) {
					while (*p && !isspace((unsigned char)*p)) p++;
					p = skip_ws(p);
					/* Status bit name or bit_num Dreg */
					int sb = parse_stsbit(p);
					if (sb >= 0) {
						word = bsetskp[i].base | (cond << 7) | (sb << 3);
						found = 1;
					} else if (parse_offset(p, &offset_val) == 0) {
						char *endp;
						strtol(p, &endp, 8);
						p = skip_ws(endp);
						int reg = parse_dreg_full(p);
						if (reg >= 0) {
							word = bsetskp[i].base | (cond << 7) | (offset_val & 0x78) | reg;
							found = 1;
						}
					}
				}
				break;
			}
		}
	}

	/* ---- Single-name bit ops: BSTC/BSTA/BLDC/BLDA/BANC/BAND/BORC/BORA ---- */
	if (!found) {
		static const struct { const char *name; int nlen; uint16_t base; } bitops[] = {
			{"BSTC", 4, 0176000}, {"BSTA", 4, 0176200},
			{"BLDC", 4, 0176400}, {"BLDA", 4, 0176600},
			{"BANC", 4, 0177000}, {"BAND", 4, 0177200},
			{"BORC", 4, 0177400}, {"BORA", 4, 0177600},
			{NULL, 0, 0}
		};
		int i;
		for (i = 0; bitops[i].name; i++) {
			if (tok_match(p, bitops[i].name)) {
				p = skip_ws(p + bitops[i].nlen);
				/* Status bit name or bit_num Dreg */
				int sb = parse_stsbit(p);
				if (sb >= 0) {
					word = bitops[i].base | (sb << 3);
					found = 1;
				} else if (parse_offset(p, &offset_val) == 0) {
					char *endp;
					strtol(p, &endp, 8);
					p = skip_ws(endp);
					int reg = parse_dreg_full(p);
					if (reg >= 0) {
						word = bitops[i].base | (offset_val & 0x78) | reg;
						found = 1;
					}
				}
				break;
			}
		}
	}

	if (!found) {
		return -1;
	}

	/* Encode output */
	if (a->big_endian) {
		outbuf[0] = (word >> 8) & 0xFF;
		outbuf[1] = word & 0xFF;
	} else {
		outbuf[0] = word & 0xFF;
		outbuf[1] = (word >> 8) & 0xFF;
	}

	rz_asm_op_set_buf(op, outbuf, 2);
	op->size = 2;
	return 2;
}

/* ---- Disassembler ---- */

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len < 2) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 0;
		return 0;
	}

	uint16_t word;
	if (a->big_endian) {
		word = ((uint16_t)buf[0] << 8) | buf[1];
	} else {
		word = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
	}

	int cpu_mode = (a->cpu && strstr(a->cpu, "nd110")) ? CPU_ND110 : CPU_ND100;

	char mnemonic[64];
	nd100_disasm(word, mnemonic, sizeof(mnemonic), cpu_mode);

	/* Annotate MON calls and IOX device registers */
	char annotated[256];
	if ((word & 0xFF00) == 0xD600) {
		int mon_num = word & 0xFF;
		const struct mon_call *mc = mon_lookup(mon_num);
		if (mc) {
			snprintf(annotated, sizeof(annotated),
				"%s ; %s - %s", mnemonic,
				mc->short_name, mc->name);
			rz_asm_op_set_asm(op, annotated);
		} else {
			rz_asm_op_set_asm(op, mnemonic);
		}
	} else if ((word & 0xF800) == 0xE800) {
		int iox_addr = word & 0x07FF;
		const struct iox_device *dev = iox_lookup(iox_addr);
		if (dev) {
			snprintf(annotated, sizeof(annotated),
				"%s ; %s %s (%s)",
				mnemonic, dev->device,
				dev->regname, dev->direction);
			rz_asm_op_set_asm(op, annotated);
		} else {
			rz_asm_op_set_asm(op, mnemonic);
		}
	} else {
		rz_asm_op_set_asm(op, mnemonic);
	}

	op->size = 2;
	return 2;
}

RzAsmPlugin rz_asm_plugin_nd100 = {
	.name = "nd100",
	.arch = "nd100",
	.author = "Ronny Hansen",
	.version = "1.0.5",
	.cpus = "nd100,nd110",
	.desc = "Norsk Data ND-100/ND-110 disassembler and assembler",
	.license = "LGPL3",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_BI,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_nd100,
	.version = RZ_VERSION,
};
#endif
