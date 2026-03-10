/*
 * rz_parse_nd100.c - Rizin parse plugin for ND-100/ND-110 pseudo-code
 *
 * Translates ND-100 assembly mnemonics into C-like pseudo-code for
 * the pdc (pseudo-disassembly) command.
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <rz_parse.h>
#include <rz_lib.h>

/*
 * Parse one disassembly line into pseudo-code.
 * Input:  "LDA ,B 10"
 * Output: "a = *(b + 10)"
 */
static bool nd100_parse(RzParse *p, const char *assembly, RzStrBuf *sb) {
	const char *s = assembly;
	char mnemonic[32];
	char operands[128];
	int i;

	if (!assembly || !*assembly) {
		rz_strbuf_set(sb, "");
		return true;
	}

	/* Skip leading whitespace */
	while (isspace((unsigned char)*s)) s++;

	/* Extract mnemonic */
	for (i = 0; i < (int)sizeof(mnemonic) - 1 && *s && !isspace((unsigned char)*s); i++) {
		mnemonic[i] = *s++;
	}
	mnemonic[i] = '\0';

	/* Extract operands (skip space, stop at semicolon comment) */
	while (isspace((unsigned char)*s)) s++;
	for (i = 0; i < (int)sizeof(operands) - 1 && *s && *s != ';'; i++) {
		operands[i] = *s++;
	}
	operands[i] = '\0';
	/* Trim trailing spaces from operands */
	while (i > 0 && isspace((unsigned char)operands[i-1])) operands[--i] = '\0';

	/* ---- Memory reference to pseudo-code ----
	 * Format: "MNEM <relmode> <offset>"
	 * relmode tokens: ,B  I  ,X  I ,B  I ,X  ,X ,B  I ,B ,X
	 * Pseudo-code: *(addr) for loads/stores
	 */

	/* Helper: build effective address string from operand tokens */
	/* We'll parse the addressing mode and offset from the operands string */
	char ea[64];
	ea[0] = '\0';

	/* Detect addressing mode components from operand string */
	{
		const char *op = operands;
		int has_i = 0, has_b = 0, has_x = 0;
		char off_str[32];
		off_str[0] = '\0';

		while (isspace((unsigned char)*op)) op++;
		if (*op == 'I' && (op[1] == ' ' || op[1] == '\t' || op[1] == ',')) {
			has_i = 1;
			op++;
			while (isspace((unsigned char)*op)) op++;
		}
		while (*op == ',') {
			op++;
			while (isspace((unsigned char)*op)) op++;
			if (*op == 'B' || *op == 'b') { has_b = 1; op++; }
			else if (*op == 'X' || *op == 'x') { has_x = 1; op++; }
			while (isspace((unsigned char)*op)) op++;
		}
		/* Remaining is the offset */
		strncpy(off_str, op, sizeof(off_str) - 1);
		off_str[sizeof(off_str) - 1] = '\0';
		/* Trim */
		int ol = strlen(off_str);
		while (ol > 0 && isspace((unsigned char)off_str[ol-1])) off_str[--ol] = '\0';

		/* Build EA expression */
		if (has_b && !has_i && !has_x) {
			if (off_str[0]) snprintf(ea, sizeof(ea), "b + %s", off_str);
			else snprintf(ea, sizeof(ea), "b");
		} else if (has_b && has_x && !has_i) {
			snprintf(ea, sizeof(ea), "b + x + %s", off_str);
		} else if (has_x && !has_b && !has_i) {
			snprintf(ea, sizeof(ea), "x + %s", off_str);
		} else if (has_i && has_b && !has_x) {
			snprintf(ea, sizeof(ea), "*(%s + b)", off_str[0] ? off_str : "0");
		} else if (has_i && !has_b && !has_x) {
			snprintf(ea, sizeof(ea), "*(%s)", off_str[0] ? off_str : "0");
		} else if (has_i && has_b && has_x) {
			snprintf(ea, sizeof(ea), "*(b + %s) + x", off_str[0] ? off_str : "0");
		} else if (has_i && !has_b && has_x) {
			snprintf(ea, sizeof(ea), "*(%s) + x", off_str[0] ? off_str : "0");
		} else {
			/* Direct */
			if (off_str[0]) snprintf(ea, sizeof(ea), "%s", off_str);
			else ea[0] = '\0';
		}
	}

	/* ---- Pattern matching ---- */

	/* Load instructions */
	if (!strcmp(mnemonic, "LDA")) {
		rz_strbuf_setf(sb, "a = *(%s)", ea);
	} else if (!strcmp(mnemonic, "LDT")) {
		rz_strbuf_setf(sb, "t = *(%s)", ea);
	} else if (!strcmp(mnemonic, "LDX")) {
		rz_strbuf_setf(sb, "x = *(%s)", ea);
	} else if (!strcmp(mnemonic, "LDD")) {
		rz_strbuf_setf(sb, "d = *(%s)", ea);
	} else if (!strcmp(mnemonic, "LDF")) {
		rz_strbuf_setf(sb, "f = *(%s)", ea);

	/* Store instructions */
	} else if (!strcmp(mnemonic, "STA")) {
		rz_strbuf_setf(sb, "*(%s) = a", ea);
	} else if (!strcmp(mnemonic, "STT")) {
		rz_strbuf_setf(sb, "*(%s) = t", ea);
	} else if (!strcmp(mnemonic, "STX")) {
		rz_strbuf_setf(sb, "*(%s) = x", ea);
	} else if (!strcmp(mnemonic, "STD")) {
		rz_strbuf_setf(sb, "*(%s) = d", ea);
	} else if (!strcmp(mnemonic, "STF")) {
		rz_strbuf_setf(sb, "*(%s) = f", ea);
	} else if (!strcmp(mnemonic, "STZ")) {
		rz_strbuf_setf(sb, "*(%s) = 0", ea);

	/* Arithmetic */
	} else if (!strcmp(mnemonic, "ADD")) {
		rz_strbuf_setf(sb, "a += *(%s)", ea);
	} else if (!strcmp(mnemonic, "SUB")) {
		rz_strbuf_setf(sb, "a -= *(%s)", ea);
	} else if (!strcmp(mnemonic, "MPY")) {
		rz_strbuf_setf(sb, "a *= *(%s)", ea);
	} else if (!strcmp(mnemonic, "AND")) {
		rz_strbuf_setf(sb, "a &= *(%s)", ea);
	} else if (!strcmp(mnemonic, "ORA")) {
		rz_strbuf_setf(sb, "a |= *(%s)", ea);
	} else if (!strcmp(mnemonic, "MIN")) {
		rz_strbuf_setf(sb, "if (++*(%s) == 0) skip", ea);

	/* Floating point */
	} else if (!strcmp(mnemonic, "FAD")) {
		rz_strbuf_setf(sb, "f += *(%s)", ea);
	} else if (!strcmp(mnemonic, "FSB")) {
		rz_strbuf_setf(sb, "f -= *(%s)", ea);
	} else if (!strcmp(mnemonic, "FMU")) {
		rz_strbuf_setf(sb, "f *= *(%s)", ea);
	} else if (!strcmp(mnemonic, "FDV")) {
		rz_strbuf_setf(sb, "f /= *(%s)", ea);

	/* Branch instructions */
	} else if (!strcmp(mnemonic, "JMP")) {
		rz_strbuf_setf(sb, "goto %s", operands);
	} else if (!strcmp(mnemonic, "JPL")) {
		rz_strbuf_setf(sb, "call %s", operands);
	} else if (!strcmp(mnemonic, "JAP")) {
		rz_strbuf_setf(sb, "if (a > 0) goto %s", operands);
	} else if (!strcmp(mnemonic, "JAN")) {
		rz_strbuf_setf(sb, "if (a < 0) goto %s", operands);
	} else if (!strcmp(mnemonic, "JAZ")) {
		rz_strbuf_setf(sb, "if (a == 0) goto %s", operands);
	} else if (!strcmp(mnemonic, "JAF")) {
		rz_strbuf_setf(sb, "if (a != 0) goto %s", operands);
	} else if (!strcmp(mnemonic, "JPC")) {
		rz_strbuf_setf(sb, "if (carry) goto %s", operands);
	} else if (!strcmp(mnemonic, "JNC")) {
		rz_strbuf_setf(sb, "if (!carry) goto %s", operands);
	} else if (!strcmp(mnemonic, "JXZ")) {
		rz_strbuf_setf(sb, "if (x == 0) goto %s", operands);
	} else if (!strcmp(mnemonic, "JXN")) {
		rz_strbuf_setf(sb, "if (x != 0) goto %s", operands);

	/* Return/Exit */
	} else if (!strcmp(mnemonic, "EXIT")) {
		rz_strbuf_set(sb, "return");
	} else if (!strcmp(mnemonic, "LEAVE") || !strcmp(mnemonic, "ELEAV")) {
		rz_strbuf_set(sb, "return");

	/* SKP instruction */
	} else if (!strcmp(mnemonic, "SKP")) {
		/* Already formatted as "SKP IF <dst> <cond> <src>" */
		rz_strbuf_setf(sb, "if (%s) skip", operands);

	/* Argument instructions */
	} else if (!strcmp(mnemonic, "SAA")) {
		rz_strbuf_setf(sb, "a = %s", operands);
	} else if (!strcmp(mnemonic, "SAB")) {
		rz_strbuf_setf(sb, "b = %s", operands);
	} else if (!strcmp(mnemonic, "SAT")) {
		rz_strbuf_setf(sb, "t = %s", operands);
	} else if (!strcmp(mnemonic, "SAX")) {
		rz_strbuf_setf(sb, "x = %s", operands);
	} else if (!strcmp(mnemonic, "AAA")) {
		rz_strbuf_setf(sb, "a += %s", operands);
	} else if (!strcmp(mnemonic, "AAB")) {
		rz_strbuf_setf(sb, "b += %s", operands);
	} else if (!strcmp(mnemonic, "AAT")) {
		rz_strbuf_setf(sb, "t += %s", operands);
	} else if (!strcmp(mnemonic, "AAX")) {
		rz_strbuf_setf(sb, "x += %s", operands);

	/* Register operations */
	} else if (!strcmp(mnemonic, "RADD")) {
		rz_strbuf_setf(sb, "reg_add(%s)", operands);
	} else if (!strcmp(mnemonic, "RSUB")) {
		rz_strbuf_setf(sb, "reg_sub(%s)", operands);
	} else if (!strcmp(mnemonic, "SWAP")) {
		rz_strbuf_setf(sb, "swap(%s)", operands);
	} else if (!strcmp(mnemonic, "RAND")) {
		rz_strbuf_setf(sb, "reg_and(%s)", operands);
	} else if (!strcmp(mnemonic, "REXO")) {
		rz_strbuf_setf(sb, "reg_xor(%s)", operands);
	} else if (!strcmp(mnemonic, "RORA")) {
		rz_strbuf_setf(sb, "reg_or(%s)", operands);
	} else if (!strcmp(mnemonic, "RMPY")) {
		rz_strbuf_setf(sb, "reg_mul(%s)", operands);
	} else if (!strcmp(mnemonic, "RDIV")) {
		rz_strbuf_setf(sb, "reg_div(%s)", operands);
	/* COPY is disassembled as RADD CLD - handle the common prologue */
	} else if (!strncmp(mnemonic, "COPY", 4)) {
		rz_strbuf_setf(sb, "copy(%s)", operands);

	/* MON - system call */
	} else if (!strcmp(mnemonic, "MON")) {
		/* The annotation after ; has the call name */
		const char *comment = strchr(assembly, ';');
		if (comment) {
			comment++;
			while (isspace((unsigned char)*comment)) comment++;
			/* Extract short name (up to ' - ') */
			char name[32];
			for (i = 0; i < (int)sizeof(name) - 1 && comment[i] && comment[i] != ' '; i++) {
				name[i] = comment[i];
			}
			name[i] = '\0';
			rz_strbuf_setf(sb, "%s()", name);
		} else {
			rz_strbuf_setf(sb, "syscall(%s)", operands);
		}

	/* IOX - I/O */
	} else if (!strcmp(mnemonic, "IOX")) {
		const char *comment = strchr(assembly, ';');
		if (comment) {
			comment++;
			while (isspace((unsigned char)*comment)) comment++;
			rz_strbuf_setf(sb, "io(%s)", comment);
		} else {
			rz_strbuf_setf(sb, "io(0%s)", operands);
		}

	/* IOT */
	} else if (!strcmp(mnemonic, "IOT")) {
		rz_strbuf_setf(sb, "iot(0%s)", operands);

	/* Shift instructions */
	} else if (!strcmp(mnemonic, "SHT")) {
		rz_strbuf_setf(sb, "a <<= %s", operands);
	} else if (!strcmp(mnemonic, "SHA")) {
		rz_strbuf_setf(sb, "a = arith_shift(a, %s)", operands);
	} else if (!strcmp(mnemonic, "SHD")) {
		rz_strbuf_setf(sb, "d <<= %s", operands);
	} else if (!strcmp(mnemonic, "SAD")) {
		rz_strbuf_setf(sb, "d = arith_shift(d, %s)", operands);

	/* Stack/frame */
	} else if (!strcmp(mnemonic, "ENTR")) {
		rz_strbuf_set(sb, "enter_frame()");
	} else if (!strcmp(mnemonic, "INIT")) {
		rz_strbuf_set(sb, "init_stack()");

	/* Skip-type instructions */
	} else if (!strcmp(mnemonic, "DNZ")) {
		rz_strbuf_setf(sb, "if (--*(%s) != 0) skip", operands);
	} else if (!strcmp(mnemonic, "NLZ")) {
		rz_strbuf_setf(sb, "if (nlz(a) == %s) skip", operands);
	} else if (!strcmp(mnemonic, "IOXT")) {
		rz_strbuf_set(sb, "if (io_done) skip");

	/* Bit operations */
	} else if (!strncmp(mnemonic, "BSKP", 4)) {
		rz_strbuf_setf(sb, "if (bit_test(%s)) skip", operands);
	} else if (!strncmp(mnemonic, "BSET", 4)) {
		rz_strbuf_setf(sb, "bit_set(%s)", operands);
	} else if (!strncmp(mnemonic, "BSTC", 4) || !strncmp(mnemonic, "BSTA", 4)) {
		rz_strbuf_setf(sb, "bit_store(%s)", operands);
	} else if (!strncmp(mnemonic, "BLDC", 4) || !strncmp(mnemonic, "BLDA", 4)) {
		rz_strbuf_setf(sb, "bit_load(%s)", operands);
	} else if (!strncmp(mnemonic, "BANC", 4) || !strncmp(mnemonic, "BAND", 4)) {
		rz_strbuf_setf(sb, "bit_and(%s)", operands);
	} else if (!strncmp(mnemonic, "BORC", 4) || !strncmp(mnemonic, "BORA", 4)) {
		rz_strbuf_setf(sb, "bit_or(%s)", operands);

	/* Privileged */
	} else if (!strcmp(mnemonic, "WAIT")) {
		rz_strbuf_set(sb, "halt()");
	} else if (!strcmp(mnemonic, "OPCOM")) {
		rz_strbuf_set(sb, "operator_call()");
	} else if (!strcmp(mnemonic, "TRA")) {
		rz_strbuf_setf(sb, "a = intreg[%s]", operands);
	} else if (!strcmp(mnemonic, "TRR")) {
		rz_strbuf_setf(sb, "intreg[%s] = a", operands);
	} else if (!strcmp(mnemonic, "IOF")) {
		rz_strbuf_set(sb, "interrupts_off()");
	} else if (!strcmp(mnemonic, "ION")) {
		rz_strbuf_set(sb, "interrupts_on()");
	} else if (!strcmp(mnemonic, "POF")) {
		rz_strbuf_set(sb, "paging_off()");
	} else if (!strcmp(mnemonic, "PON")) {
		rz_strbuf_set(sb, "paging_on()");

	/* NOP */
	} else if (!strcmp(mnemonic, "ROP") || !strcmp(mnemonic, "NOP")) {
		rz_strbuf_set(sb, "nop");

	/* Byte operations */
	} else if (!strcmp(mnemonic, "LBYT")) {
		rz_strbuf_set(sb, "a = load_byte()");
	} else if (!strcmp(mnemonic, "SBYT")) {
		rz_strbuf_set(sb, "store_byte(a)");
	} else if (!strcmp(mnemonic, "MOVB")) {
		rz_strbuf_set(sb, "move_bytes()");
	} else if (!strcmp(mnemonic, "MOVBF")) {
		rz_strbuf_set(sb, "move_bytes_fast()");
	} else if (!strcmp(mnemonic, "MOVEW")) {
		rz_strbuf_set(sb, "move_words()");
	} else if (!strcmp(mnemonic, "BFILL")) {
		rz_strbuf_set(sb, "block_fill()");

	/* Default: pass through */
	} else {
		rz_strbuf_setf(sb, "%s %s", mnemonic, operands);
	}

	return true;
}

RzParsePlugin rz_parse_plugin_nd100_pseudo = {
	.name = "nd100.pseudo",
	.desc = "ND-100 pseudo-code",
	.parse = &nd100_parse,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_nd100_pseudo,
	.version = RZ_VERSION,
};
#endif
