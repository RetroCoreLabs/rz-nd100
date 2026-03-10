/*
 * rz_analysis_nd100.c - Rizin analysis plugin for ND-100/ND-110
 *
 * Provides control flow information (branch targets, call/ret detection)
 * so Rizin/Cutter can build CFGs, show branch arrows, and xrefs.
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <rz_analysis.h>
#include <rz_search.h>
#include <rz_lib.h>
#include "nd100_disasm.h"

static int nd100_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return 1;
	default:
		return -1;
	}
}

static int nd100_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr,
		    const ut8 *data, int len, RzAnalysisOpMask mask) {
	uint16_t word;
	uint16_t top5, top8;
	int offset;

	if (len < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 0;
		return 0;
	}

	op->size = 2;
	op->addr = addr;

	if (a->big_endian) {
		word = ((uint16_t)data[0] << 8) | data[1];
	} else {
		word = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
	}

	top5 = word & 0xF800;
	top8 = word & 0xFF00;

	/*
	 * ND-100 instruction classification for control flow:
	 *
	 * JMP  (0124xxx) - unconditional jump, 8-bit signed offset
	 * JPL  (0134xxx) - jump to subroutine (call), various addressing
	 * JAP  (01300xx) - jump if A positive
	 * JAN  (01304xx) - jump if A negative
	 * JAZ  (01310xx) - jump if A zero
	 * JAF  (01314xx) - jump if A nonzero
	 * JPC  (01320xx) - jump if carry set
	 * JNC  (01324xx) - jump if no carry
	 * JXZ  (01330xx) - jump if X zero
	 * JXN  (01334xx) - jump if X nonzero
	 * MON  (0153xxx) - monitor call (syscall)
	 * EXIT (0146142) - return from subroutine
	 * LEAVE/ELEAV     - return variants
	 * NLZ  (01514xx) - skip next if A leading zeros (conditional skip)
	 * DNZ  (01520xx) - decrement and skip if zero
	 * SKP  (0140xxx) - skip instruction (bits 6-7 must be 0)
	 * BSKP (01750xx-01756xx) - bit skip (ZRO/ONE/BCM/BAC)
	 * MIN  (0040xxx) - memory increment, skip on zero
	 * IOXT (0150415) - IOX with transfer complete skip
	 * SRB  (01524xx) - skip return bit
	 * ADDD/SUBD/COMD/TSET/PACK/UPACK/SHDE/RDUS (0140120-0140127)
	 *              - decimal instructions, skip on no error
	 * TSETP/RDUSP (0140516-0140517) - ND-110 decimal, skip on no error
	 * ENTR (0140135) - enter stack, 1 inline word, skip error on success
	 * INIT (0140134) - init stack, 6 inline words, skip error on success
	 * WAIT (01510xx) - halt
	 */

	/* Signed 8-bit branch offset (word-addressed, so *2 for byte offset) */
	offset = (signed char)(word & 0xFF);

	if (top5 == 0xA800) {
		/* JMP - unconditional jump (octal 0124000) */
		uint16_t relmode = (word >> 8) & 0x07;
		if (relmode == 0) {
			/* Direct relative jump */
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = addr + (st64)offset * 2;
		} else {
			/* Indirect/indexed jump - target not statically known */
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
		}
		op->eob = true;
	} else if (top5 == 0xB800) {
		/* JPL - jump to subroutine (octal 0134000) */
		uint16_t relmode = (word >> 8) & 0x07;
		if (relmode == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = addr + (st64)offset * 2;
			op->fail = addr + 2;
		} else if (relmode == 2) {
			/* JPL I - indirect call (common for function pointers) */
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			op->fail = addr + 2;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->fail = addr + 2;
		}
	} else if (top5 == 0xB000) {
		/* Conditional branches: JAP/JAN/JAZ/JAF/JPC/JNC/JXZ/JXN
		 * (octal 0130000-0133777) */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + (st64)offset * 2;
		op->fail = addr + 2;
	} else if (word == 0xC05D) {
		/* ENTR (0140135) - enter stack frame.
		 * Format: ENTR / stack_demand / <error_return> / <normal code>
		 * On success: skips error_return (addr+6), on error: addr+4.
		 * Consumes 1 inline word (stack demand), total size = 4 bytes. */
		op->size = 4;
		if (len >= 4) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + 6;
			op->fail = addr + 4;
		}
	} else if (word == 0xC05C) {
		/* INIT (0140134) - initialize stack.
		 * Format: INIT / nwords / stack_start / max_size / flag /
		 *         empty / <error_return> / <normal code>
		 * Consumes 6 inline words, total size = 14 bytes.
		 * On success: skips error_return (addr+14), on error: addr+12. */
		op->size = 14;
		if (len >= 14) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + 14;
			op->fail = addr + 12;
		}
	} else if (word == 0xC09E || word == 0xC09F) {
		/* LEAVE (0140136) / ELEAV (0140137) - return from ENTR */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
	} else if (word == 0xCC62) {
		/* EXIT (0146142) = RADD CLD SP DB - return from subroutine */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
	} else if (top8 == 0xD600) {
		/* MON - monitor call (octal 0153000) */
		int mon_num = word & 0xFF;
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->val = mon_num;
		/* MON 0 (LEAVE/ExitFromProgram) does not return */
		if (mon_num == 0) {
			op->eob = true;
		}
	} else if (word == 0xD10D) {
		/* IOXT (0150415) - IOX with transfer complete skip */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top8 == 0xD200) {
		/* WAIT (0151000) - halt processor */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->eob = true;
	} else if (top8 == 0xD300) {
		/* NLZ (0151400) - skip next if A leading zeros match */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top8 == 0xD400) {
		/* DNZ (0152000) - decrement and skip if nonzero */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if ((word & 0xFF80) == 0xD500) {
		/* SRB (0152400) - skip return bit */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if ((word & 0xFFF8) == 0xC050) {
		/* Decimal instructions (0140120-0140127): ADDD/SUBD/COMD/TSET/
		 * PACK/UPACK/SHDE/RDUS - skip next on no error */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (word == 0xC14E || word == 0xC14F) {
		/* TSETP (0140516) / RDUSP (0140517) - ND-110 decimal,
		 * skip next on no error */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top5 == 0xC000 && (word & 0x00C0) == 0) {
		/* SKP - skip instruction (octal 0140000, low 6 bits = condition) */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top5 == 0x4000) {
		/* MIN (0040000) - memory increment, skip on zero */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top5 == 0x4800) {
		/* LDA (octal 0044000) - load A register */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
	} else if (top5 == 0x0800) {
		/* STA (octal 0004000) - store A register */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	} else if (top5 == 0x6000 || top5 == 0x6800) {
		/* ADD/SUB (octal 060000/064000) */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
	} else if (top5 == 0xE000) {
		/* IOT (octal 0160000) */
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
	} else if (top5 == 0xE800) {
		/* IOX (octal 0164000) */
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
	} else if ((word & 0xFE00) == 0xFA00) {
		/* BSKP (0175000-0175600) - bit skip (ZRO/ONE/BCM/BAC) */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if ((word & 0xFFC0) == 0xCFC0) {
		/* ROP NOOP (octal 0147700-0147777) */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}

	return op->size;
}

static RzList /*<RzSearchKeyword *>*/ *nd100_preludes(RzAnalysis *a) {
	RzList *list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}

	/*
	 * C compiler prologue: COPY SL DA (0xC838) followed by JPL I [csav]
	 * COPY SL DA = 0xC838 -> bytes 0x38 0xC8 (little-endian)
	 * JPL I xxx  = 0xBCxx -> bytes 0xxx 0xBC (little-endian, relmode=2)
	 *
	 * This is the most common function entry pattern in C-compiled code.
	 */
	rz_list_push(list, rz_search_keyword_new(
		(const ut8 *)"\x38\xc8", 2,
		NULL, 0, NULL));

	/*
	 * ENTR (0xC05D) - PLANC/COBOL stack frame entry
	 * Bytes: 0x5D 0xC0 (little-endian)
	 */
	rz_list_push(list, rz_search_keyword_new(
		(const ut8 *)"\x5d\xc0", 2,
		NULL, 0, NULL));

	/*
	 * INIT (0xC05C) - stack initialization
	 * Bytes: 0x5C 0xC0 (little-endian)
	 */
	rz_list_push(list, rz_search_keyword_new(
		(const ut8 *)"\x5c\xc0", 2,
		NULL, 0, NULL));

	return list;
}

static char *nd100_get_reg_profile(RzAnalysis *a) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	b\n"
		"=A0	a\n"
		"=R0	a\n"
		"gpr	a	.16	0	0\n"   /* A register (accumulator) */
		"gpr	t	.16	2	0\n"   /* T register */
		"gpr	x	.16	4	0\n"   /* X register (index) */
		"gpr	b	.16	6	0\n"   /* B register (frame pointer) */
		"gpr	l	.16	8	0\n"   /* L register (link/return) */
		"gpr	d	.16	10	0\n"   /* D register */
		"gpr	sp	.16	12	0\n"  /* S register (stack pointer) */
		"gpr	p	.16	14	0\n"   /* P register (program counter hw) */
		"gpr	pc	.16	16	0\n"  /* PC (virtual, for Rizin) */
		;
	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_nd100 = {
	.name = "nd100",
	.desc = "Norsk Data ND-100/ND-110 analysis",
	.license = "LGPL3",
	.arch = "nd100",
	.author = "Ronny Hansen",
	.version = "1.0.0",
	.bits = 16,
	.archinfo = &nd100_archinfo,
	.preludes = &nd100_preludes,
	.op = &nd100_op,
	.get_reg_profile = &nd100_get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_nd100,
	.version = RZ_VERSION,
};
#endif
