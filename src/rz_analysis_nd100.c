/*
 * rz_analysis_nd100.c - Rizin analysis plugin for ND-100/ND-110
 *
 * Provides control flow, opcode classification, ESIL emulation strings,
 * frame tracking, operand analysis, and function prologue detection.
 *
 * Note: ND-100 has no hardware stack. Frame management uses the B register
 * with ENTR/LEAVE conventions. stackop is used to tell Rizin about
 * B-relative frame accesses and JPL/EXIT link-register calling.
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <rz_analysis.h>
#include <rz_search.h>
#include <rz_lib.h>
#include "nd100_disasm.h"
#include "moncalls.h"

/* ---- helpers ---- */

/* Compute effective address ESIL fragment for memory-reference instructions.
 * ND-100 uses word addressing; Rizin uses byte addressing.
 * The result is an ESIL expression that leaves the byte address on the stack.
 *
 * Addressing modes (relmode bits 8-10):
 *   0: direct        EA = offset
 *   1: B-relative    EA = B + offset
 *   2: indirect      EA = [offset]
 *   3: indirect B    EA = [B + offset]
 *   4: X-indexed     EA = offset + X
 *   5: X,B           EA = B + offset + X
 *   6: indirect X    EA = [offset] + X
 *   7: indirect B,X  EA = [B + offset] + X
 *
 * ND-100 word addresses are converted to byte addresses via 2,* for
 * Rizin's memory model. Register values (b, x) are kept as word values
 * since that is what the hardware uses.
 */
static void esil_mem_ea(RzStrBuf *sb, int offset, int relmode) {
	/* Base address computation (word address) */
	switch (relmode) {
	case 0: /* direct */
		rz_strbuf_setf(sb, "%d", offset);
		break;
	case 1: /* ,B */
		rz_strbuf_setf(sb, "%d,b,+", offset);
		break;
	case 2: /* I (indirect) */
		rz_strbuf_setf(sb, "%d,2,*,[2]", offset);
		break;
	case 3: /* I ,B */
		rz_strbuf_setf(sb, "%d,b,+,2,*,[2]", offset);
		break;
	case 4: /* ,X */
		rz_strbuf_setf(sb, "%d,x,+", offset);
		break;
	case 5: /* ,X ,B */
		rz_strbuf_setf(sb, "%d,b,+,x,+", offset);
		break;
	case 6: /* I ,X */
		rz_strbuf_setf(sb, "%d,2,*,[2],x,+", offset);
		break;
	case 7: /* I ,B ,X */
		rz_strbuf_setf(sb, "%d,b,+,2,*,[2],x,+", offset);
		break;
	}
}

/* Generate ESIL for "load word from EA into register" */
static void esil_load(RzStrBuf *esil, int offset, int relmode, const char *reg) {
	RzStrBuf ea;
	rz_strbuf_init(&ea);
	esil_mem_ea(&ea, offset, relmode);
	rz_strbuf_setf(esil, "%s,2,*,[2],%s,=",
		rz_strbuf_get(&ea), reg);
	rz_strbuf_fini(&ea);
}

/* Generate ESIL for "store register to EA" */
static void esil_store(RzStrBuf *esil, int offset, int relmode, const char *reg) {
	RzStrBuf ea;
	rz_strbuf_init(&ea);
	esil_mem_ea(&ea, offset, relmode);
	rz_strbuf_setf(esil, "%s,%s,2,*,=[2]",
		reg, rz_strbuf_get(&ea));
	rz_strbuf_fini(&ea);
}

/* ---- analysis callbacks ---- */

static int nd100_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 14; /* INIT consumes 7 words (14 bytes) */
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

static int nd100_address_bits(RzAnalysis *a, int bits) {
	return 16;
}

/* Compute PC-relative branch target.
 * ND-100 uses 16-bit word addresses with signed 8-bit offset.
 * addr is in byte-address space (word_addr * 2).
 * Result is clamped to valid byte-address range to prevent
 * wrapping to huge 64-bit values that crash the analysis engine. */
static ut64 branch_target(ut64 addr, int offset) {
	st64 target = (st64)addr + (st64)offset * 2;
	if (target < 0) {
		return 0;
	}
	return (ut64)target & 0x1FFFE; /* 16-bit word address space = 128K byte addresses */
}

static int nd100_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr,
		    const ut8 *data, int len, RzAnalysisOpMask mask) {
	uint16_t word;
	uint16_t top5, top8;
	int offset;
	int relmode;
	int do_esil = (mask & RZ_ANALYSIS_OP_MASK_ESIL);

	if (!data || len < 2) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 2;
		return 2;
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

	/* Signed 8-bit offset (word-addressed, so *2 for byte offset in jumps) */
	offset = (signed char)(word & 0xFF);
	relmode = (word >> 8) & 0x07;

	/* Provide disassembly mnemonic when requested */
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		char mnemonic[64];
		int cpu_mode = (a->cpu && strstr(a->cpu, "nd110")) ? CPU_ND110 : CPU_ND100;
		nd100_disasm(word, mnemonic, sizeof(mnemonic), cpu_mode);
		op->mnemonic = rz_str_dup(mnemonic);
	}

	/* ================================================================
	 * Memory Reference Instructions (top 5 bits = opcode)
	 * ================================================================ */

	if (top5 == 0x0000) {
		/* STZ (octal 0000000) - store zero to memory */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (relmode == 1 || relmode == 3) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
		}
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "0,%s,2,*,=[2]",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}
	} else if (top5 == 0x0800) {
		/* STA (octal 0004000) - store A */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (relmode == 1 || relmode == 3) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
		}
		if (do_esil) {
			esil_store(&op->esil, offset, relmode, "a");
		}
	} else if (top5 == 0x1000) {
		/* STT (octal 0010000) - store T */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_store(&op->esil, offset, relmode, "t");
		}
	} else if (top5 == 0x1800) {
		/* STX (octal 0014000) - store X */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_store(&op->esil, offset, relmode, "x");
		}
	} else if (top5 == 0x2000) {
		/* STD (octal 0020000) - store D (double, 32-bit) */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_store(&op->esil, offset, relmode, "d");
		}
	} else if (top5 == 0x2800) {
		/* LDD (octal 0024000) - load D (double) */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_load(&op->esil, offset, relmode, "d");
		}
	} else if (top5 == 0x3000) {
		/* STF (octal 0030000) - store floating */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (top5 == 0x3800) {
		/* LDF (octal 0034000) - load floating */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (top5 == 0x4000) {
		/* MIN (octal 0040000) - memory increment, skip on zero */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil,
				"1,%s,2,*,[2],+,DUP,%s,2,*,=[2],"
				"0,==,$z,?{,4,pc,+=,}",
				rz_strbuf_get(&ea), rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}
	} else if (top5 == 0x4800) {
		/* LDA (octal 0044000) - load A */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (relmode == 1 || relmode == 3) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
		}
		if (do_esil) {
			esil_load(&op->esil, offset, relmode, "a");
		}
	} else if (top5 == 0x5000) {
		/* LDT (octal 0050000) - load T */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_load(&op->esil, offset, relmode, "t");
		}
	} else if (top5 == 0x5800) {
		/* LDX (octal 0054000) - load X */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			esil_load(&op->esil, offset, relmode, "x");
		}
	} else if (top5 == 0x6000) {
		/* ADD (octal 0060000) - add memory to A */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "%s,2,*,[2],a,+=",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}
	} else if (top5 == 0x6800) {
		/* SUB (octal 0064000) - subtract memory from A */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "%s,2,*,[2],a,-=",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}
	} else if (top5 == 0x7000) {
		/* AND (octal 0070000) - AND memory with A */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "%s,2,*,[2],a,&=",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}
	} else if (top5 == 0x7800) {
		/* ORA (octal 0074000) - OR memory with A */
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "%s,2,*,[2],a,|=",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}

	/* ================================================================
	 * Floating Point Instructions
	 * ================================================================ */

	} else if (top5 == 0x8000) {
		/* FAD (octal 0100000) */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (top5 == 0x8800) {
		/* FSB (octal 0104000) */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (top5 == 0x9000) {
		/* FMU (octal 0110000) */
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	} else if (top5 == 0x9800) {
		/* FDV (octal 0114000) */
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;

	/* ================================================================
	 * MPY - Integer Multiply
	 * ================================================================ */

	} else if (top5 == 0xA000) {
		/* MPY (octal 0120000) */
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, relmode);
			rz_strbuf_setf(&op->esil, "%s,2,*,[2],a,*=",
				rz_strbuf_get(&ea));
			rz_strbuf_fini(&ea);
		}

	/* ================================================================
	 * Branch Instructions
	 * ================================================================ */

	} else if (top5 == 0xA800) {
		/* JMP (octal 0124000) - unconditional jump */
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (relmode == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = branch_target(addr, offset);
			if (do_esil) {
				rz_strbuf_setf(&op->esil, "0x%"PFMT64x",pc,=",
					op->jump);
			}
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
		}
		op->eob = true;
	} else if (top5 == 0xB000) {
		/* Conditional branches: JAP/JAN/JAZ/JAF/JPC/JNC/JXZ/JXN */
		uint16_t cond_bits = (word >> 8) & 0x07;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = branch_target(addr, offset);
		op->fail = addr + 2;

		switch (cond_bits) {
		case 0: /* JAP - jump if A positive */
			op->cond = RZ_TYPE_COND_GT;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"a,0x8000,&,!,a,0,==,!,&,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 1: /* JAN - jump if A negative */
			op->cond = RZ_TYPE_COND_LT;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"a,0x8000,&,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 2: /* JAZ - jump if A zero */
			op->cond = RZ_TYPE_COND_EQ;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"a,0,==,$z,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 3: /* JAF - jump if A nonzero */
			op->cond = RZ_TYPE_COND_NE;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"a,0,==,!,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 4: /* JPC - jump if carry set */
			op->cond = RZ_TYPE_COND_HS;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"$c,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 5: /* JNC - jump if no carry */
			op->cond = RZ_TYPE_COND_LO;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"$c,!,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 6: /* JXZ - jump if X zero */
			op->cond = RZ_TYPE_COND_EQ;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"x,0,==,$z,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		case 7: /* JXN - jump if X nonzero */
			op->cond = RZ_TYPE_COND_NE;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"x,0,==,!,?{,0x%"PFMT64x",pc,=,}",
					op->jump);
			}
			break;
		}
	} else if (top5 == 0xB800) {
		/* JPL (octal 0134000) - jump to subroutine (call) */
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (relmode == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = branch_target(addr, offset);
			op->fail = addr + 2;
			/* JPL saves return address in L register */
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -2;
			if (do_esil) {
				rz_strbuf_setf(&op->esil,
					"pc,l,=,0x%"PFMT64x",pc,=",
					op->jump);
			}
		} else if (relmode == 2) {
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			op->fail = addr + 2;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -2;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->fail = addr + 2;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -2;
		}

	/* ================================================================
	 * 0140xxx block: SKP, decimal, stack, register ops, etc.
	 * ================================================================ */

	} else if (word == 0xC05D) {
		/* ENTR (0140135) - allocate frame via B register.
		 * ENTR / frame_demand / <error> / <normal>
		 * Success: skip to addr+6, error: addr+4 */
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (len >= 4) {
			op->size = 4;
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + 6;
			op->fail = addr + 4;
			op->stackop = RZ_ANALYSIS_STACK_INC;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		}
	} else if (word == 0xC05C) {
		/* INIT (0140134) - initialize frame area.
		 * Consumes 6 inline words, total size = 14 bytes.
		 * Success: addr+14, error: addr+12 */
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (len >= 14) {
			op->size = 14;
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + 14;
			op->fail = addr + 12;
			op->stackop = RZ_ANALYSIS_STACK_RESET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		}
	} else if (word == 0xC09E || word == 0xC09F) {
		/* LEAVE (0140136) / ELEAV (0140137) - return from ENTR */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		if (do_esil) {
			rz_strbuf_set(&op->esil, "l,pc,=");
		}
	} else if (word == 0xCC62) {
		/* EXIT (0146142) = RADD CLD SP DB - return from subroutine */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		if (do_esil) {
			rz_strbuf_set(&op->esil, "l,pc,=");
		}
	} else if (top5 == 0xC000 && (word & 0x00C0) == 0) {
		/* SKP (octal 0140000) - skip instruction
		 * bits 0-2: dst register, bits 3-5: src register, bits 8-10: condition */
		int dst_reg = word & 0x0007;
		int src_reg = (word >> 3) & 0x0007;
		int skip_cond = (word >> 8) & 0x0007;
		static const char *sr[] = {"0","d","p","b","l","a","t","x"};

		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4; /* skip next word */
		op->fail = addr + 2;

		switch (skip_cond) {
		case 0: op->cond = RZ_TYPE_COND_EQ; break;  /* EQL */
		case 1: op->cond = RZ_TYPE_COND_GE; break;  /* GEQ */
		case 2: op->cond = RZ_TYPE_COND_GT; break;  /* GRE */
		case 3: op->cond = RZ_TYPE_COND_GT; break;  /* MGRE (magnitude) */
		case 4: op->cond = RZ_TYPE_COND_EQ; break;  /* UEQ (unsigned) */
		case 5: op->cond = RZ_TYPE_COND_LT; break;  /* LSS */
		case 6: op->cond = RZ_TYPE_COND_LT; break;  /* LST (magnitude) */
		case 7: op->cond = RZ_TYPE_COND_LT; break;  /* MLST (magnitude) */
		}

		if (do_esil) {
			const char *d = sr[dst_reg];
			const char *s = sr[src_reg];
			/* Simplified ESIL - compare src vs dst */
			switch (skip_cond) {
			case 0: /* EQL */
				rz_strbuf_setf(&op->esil,
					"%s,%s,==,$z,?{,0x%"PFMT64x",pc,=,}",
					s, d, op->jump);
				break;
			case 1: /* GEQ */
				rz_strbuf_setf(&op->esil,
					"%s,%s,>=,?{,0x%"PFMT64x",pc,=,}",
					s, d, op->jump);
				break;
			case 2: /* GRE */
				rz_strbuf_setf(&op->esil,
					"%s,%s,>,?{,0x%"PFMT64x",pc,=,}",
					s, d, op->jump);
				break;
			case 5: /* LSS */
				rz_strbuf_setf(&op->esil,
					"%s,%s,<,?{,0x%"PFMT64x",pc,=,}",
					s, d, op->jump);
				break;
			default:
				/* For MGRE/UEQ/LST/MLST use simplified compare */
				rz_strbuf_setf(&op->esil,
					"%s,%s,==,$z,?{,0x%"PFMT64x",pc,=,}",
					s, d, op->jump);
				break;
			}
		}

	/* Decimal instructions (0140120-0140127): skip on no error */
	} else if ((word & 0xFFF8) == 0xC050) {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (word == 0xC14E || word == 0xC14F) {
		/* TSETP / RDUSP - ND-110 decimal, skip on no error */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;

	/* ================================================================
	 * Register Operations (octal 0144000-0147777)
	 * ================================================================ */

	} else if ((word & 0xFFC0) == 0xC800) {
		/* SWAP (octal 0144000) - swap registers */
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xC840) {
		/* SWAP CLD (octal 0144100) */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xC880) {
		/* SWAP CM1 (octal 0144200) - swap with complement */
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xC8C0) {
		/* SWAP CM1 CLD (octal 0144300) - complement and clear */
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xC800) {
		/* Other SWAP variants */
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xCA00) {
		/* RAND (octal 0144400) - register AND */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xCA40) {
		/* RAND CLD (octal 0144500) */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xCA00) {
		/* RAND variants */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xCC00) {
		/* REXO (octal 0145000) - register XOR */
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xCE00) {
		/* RORA (octal 0145400) - register OR */
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	/* RADD (octal 0146000) - register add */
	} else if ((word & 0xFFC0) == 0xD000) {
		/* RADD (no flags) */
		static const char *sr[] = {"0","d","p","b","l","a","t","x"};
		int src = (word >> 3) & 0x07;
		int dst = word & 0x07;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%s,%s,+=", sr[src], sr[dst]);
		}
	} else if ((word & 0xFFC0) == 0xD040) {
		/* RADD CLD (octal 0146100) - copy register (src->dst, clear src)
		 * Special case: EXIT = RADD CLD SP DB (0146142) handled above */
		static const char *sr[] = {"0","d","p","b","l","a","t","x"};
		int src = (word >> 3) & 0x07;
		int dst = word & 0x07;
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		/* COPY SL DA = RADD CLD SA DL (copy A to L, A to D... wait)
		 * Actually: COPY SL DA means src=L dst=A with CLD (clear L)
		 * This is the function prologue: save link register */
		if (do_esil) {
			rz_strbuf_setf(&op->esil,
				"%s,%s,=,0,%s,=", sr[src], sr[dst], sr[src]);
		}
	} else if ((word & 0xFFC0) == 0xD080) {
		/* RADD CM1 (octal 0146200) - register negate-add */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xD0C0) {
		/* RADD CM1 CLD (octal 0146300) - negate and move */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xD200) {
		/* RADD AD1 (octal 0146400) - add with increment */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xD180) {
		/* RSUB (octal 0146600) - register subtract */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFE00) == 0xD400) {
		/* RADD ADC (octal 0147000) - add with carry */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFFC0) == 0xCFC0) {
		/* ROP NOOP (octal 0147700-0147777) */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (do_esil) {
			rz_strbuf_set(&op->esil, "");
		}

	/* RMPY (octal 0141200) */
	} else if ((word & 0xFFC0) == 0xC280) {
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	/* RDIV (octal 0141600) */
	} else if ((word & 0xFFC0) == 0xC380) {
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	/* LBYT (octal 0142200) */
	} else if ((word & 0xFFC0) == 0xC480) {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	/* SBYT (octal 0142600) */
	} else if ((word & 0xFFC0) == 0xC580) {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	/* MOVB/MOVBF/BFILL (octal 0140130-0140132) - block move/fill */
	} else if (word == 0xC058 || word == 0xC059 || word == 0xC05A) {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	/* MOVEW (octal 0143100) */
	} else if ((word & 0xFFC0) == 0xC640) {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	/* EXR (octal 0140600) - execute register as instruction */
	} else if ((word & 0xFFC0) == 0xC180) {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	/* ================================================================
	 * 0150xxx block: TRA/TRR/MCL/MST, OPCOM, IOF/ION, WAIT, etc.
	 * ================================================================ */

	} else if ((word & 0xFFC0) == 0xD000 + 0x800) {
		/* Already handled above in RADD block */
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	} else if ((word & 0xFFF0) == 0xD000) {
		/* TRA (octal 0150000) - transfer from internal register to A */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if ((word & 0xFFF0) == 0xD040) {
		/* TRR (octal 0150100) - transfer A to internal register */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if ((word & 0xFFF0) == 0xD080) {
		/* MCL (octal 0150200) - mask clear internal register */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if ((word & 0xFFF0) == 0xD0C0) {
		/* MST (octal 0150300) - mask set internal register */
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;

	} else if (word == 0xD100) {
		/* OPCOM (octal 0150400) */
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD101) {
		/* IOF (octal 0150401) - interrupts off */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD102) {
		/* ION (octal 0150402) - interrupts on */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD104) {
		/* POF (octal 0150404) - paging off */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD105) {
		/* PIOF (octal 0150405) - paging+interrupts off */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD106) {
		/* SEX (octal 0150406) - set extended addressing */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD107) {
		/* REX (octal 0150407) - reset extended addressing */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD108) {
		/* PON (octal 0150410) - paging on */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD10A) {
		/* PION (octal 0150412) - paging+interrupts on */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD10D) {
		/* IOXT (octal 0150415) - IOX with transfer complete skip */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (word == 0xD10E) {
		/* EXAM (octal 0150416) - examine memory */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (word == 0xD10F) {
		/* DEPO (octal 0150417) - deposit to memory */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (top8 == 0xD200) {
		/* WAIT (octal 0151000) - halt */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->eob = true;
	} else if (top8 == 0xD300) {
		/* NLZ (octal 0151400) - skip on leading zeros */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if (top8 == 0xD400) {
		/* DNZ (octal 0152000) - decrement and skip if nonzero */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;
		if (do_esil) {
			RzStrBuf ea;
			rz_strbuf_init(&ea);
			esil_mem_ea(&ea, offset, 0);
			rz_strbuf_setf(&op->esil,
				"%s,2,*,[2],1,-,DUP,%s,2,*,=[2],"
				"0,==,!,?{,0x%"PFMT64x",pc,=,}",
				rz_strbuf_get(&ea), rz_strbuf_get(&ea),
				op->jump);
			rz_strbuf_fini(&ea);
		}
	} else if ((word & 0xFF80) == 0xD500) {
		/* SRB (octal 0152400) - skip return bit */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;

	/* LRB (octal 0152600) */
	} else if ((word & 0xFF80) == 0xD580) {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	/* IRW (octal 0153400) - internal register write */
	} else if ((word & 0xFF80) == 0xD700) {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	/* IRR (octal 0153600) - internal register read */
	} else if ((word & 0xFF80) == 0xD780) {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;

	/* ================================================================
	 * MON (octal 0153000) - monitor call
	 * ================================================================ */

	} else if (top8 == 0xD600) {
		int mon_num = word & 0xFF;
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = mon_num;
		/* MON 0 (LEAVE/ExitFromProgram) does not return */
		if (mon_num == 0) {
			op->eob = true;
		}
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,TRAP", mon_num);
		}

	/* ================================================================
	 * Shift Instructions (octal 0154000-0155777)
	 * ================================================================ */

	} else if ((word & 0xFE00) == 0xD800) {
		/* SHT/SHD/SHA/SAD */
		uint16_t sh_type = (word >> 7) & 0x03;
		int sh_count = word & 0x3F;
		int sh_neg = (word >> 5) & 1;
		if (sh_neg) {
			sh_count = (~(sh_count | 0xFFC0) + 1) & 0x3F;
		}

		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		if (sh_neg) {
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		}

		if (do_esil && sh_type == 0) {
			/* SHT - logical shift on A register */
			if (sh_neg) {
				rz_strbuf_setf(&op->esil, "%d,a,>>=", sh_count);
			} else {
				rz_strbuf_setf(&op->esil, "%d,a,<<=", sh_count);
			}
		}

	/* ================================================================
	 * I/O Instructions
	 * ================================================================ */

	} else if (top5 == 0xE000) {
		/* IOT (octal 0160000) */
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;
	} else if (top5 == 0xE800) {
		/* IOX (octal 0164000) */
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		op->family = RZ_ANALYSIS_OP_FAMILY_IO;

	/* ================================================================
	 * Argument Instructions (octal 0170000-0173777)
	 * SA* = set register, AA* = add to register
	 * ================================================================ */

	} else if (top8 == 0xF000) {
		/* SAB (octal 0170000) - set B = offset */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,b,=", offset);
		}
	} else if (top8 == 0xF100) {
		/* SAA (octal 0170400) - set A = offset */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,a,=", offset);
		}
	} else if (top8 == 0xF200) {
		/* SAT (octal 0171000) - set T = offset */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,t,=", offset);
		}
	} else if (top8 == 0xF300) {
		/* SAX (octal 0171400) - set X = offset */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,x,=", offset);
		}
	} else if (top8 == 0xF400) {
		/* AAB (octal 0172000) - add offset to B */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,b,+=", offset);
		}
	} else if (top8 == 0xF500) {
		/* AAA (octal 0172400) - add offset to A */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,a,+=", offset);
		}
	} else if (top8 == 0xF600) {
		/* AAT (octal 0173000) - add offset to T */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,t,+=", offset);
		}
	} else if (top8 == 0xF700) {
		/* AAX (octal 0173400) - add offset to X */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->val = offset;
		if (do_esil) {
			rz_strbuf_setf(&op->esil, "%d,x,+=", offset);
		}

	/* ================================================================
	 * Bit Operations (octal 0174000-0177777)
	 * ================================================================ */

	} else if ((word & 0xFE00) == 0xFA00) {
		/* BSKP (0175000-0175600) - bit skip */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		op->jump = addr + 4;
		op->fail = addr + 2;
	} else if ((word & 0xFE00) == 0xF800) {
		/* BSET (0174000-0174600) - bit set */
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else if ((word & 0xFC00) == 0xFC00) {
		/* BSTC/BSTA/BLDC/BLDA/BANC/BAND/BORC/BORA */
		op->type = RZ_ANALYSIS_OP_TYPE_AND; /* bit manipulation */
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	/* ================================================================
	 * Remaining 014xxxx instructions not caught above
	 * ================================================================ */

	} else if (top5 == 0xC000) {
		/* Catch-all for 0140xxx block (USER instructions, etc.) */
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
	}

	return op->size;
}

static RzList /*<RzSearchKeyword *>*/ *nd100_preludes(RzAnalysis *a) {
	RzList *list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}

	if (a->big_endian) {
		/* Big-endian (BPUN format) */

		/* C compiler prologue: COPY SL DA (0xC838) */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\xc8\x38", 2,
			NULL, 0, NULL));

		/* ENTR (0xC05D) - PLANC/COBOL frame entry */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\xc0\x5d", 2,
			NULL, 0, NULL));

		/* INIT (0xC05C) - frame area initialization */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\xc0\x5c", 2,
			NULL, 0, NULL));
	} else {
		/* Little-endian (a.out16 format) */

		/* C compiler prologue: COPY SL DA (0xC838) */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\x38\xc8", 2,
			NULL, 0, NULL));

		/* ENTR (0xC05D) - PLANC/COBOL frame entry */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\x5d\xc0", 2,
			NULL, 0, NULL));

		/* INIT (0xC05C) - frame area initialization */
		rz_list_push(list, rz_search_keyword_new(
			(const ut8 *)"\x5c\xc0", 2,
			NULL, 0, NULL));
	}

	return list;
}

static char *nd100_get_reg_profile(RzAnalysis *a) {
	/* ND-100 has no hardware stack. The B register serves as a
	 * frame pointer in the ENTR/LEAVE calling convention.
	 * Register 0 (S) is the Status register, not a stack pointer.
	 * =SP is mapped to B for Rizin stack variable detection since
	 * B-relative accesses are the "stack frame" on this architecture. */
	const char *p =
		"=PC	pc\n"
		"=SP	b\n"
		"=BP	b\n"
		"=A0	a\n"
		"=R0	a\n"
		"gpr	s	.16	0	0\n"   /* S register (status) */
		"gpr	d	.16	2	0\n"   /* D register */
		"gpr	p	.16	4	0\n"   /* P register (program counter hw) */
		"gpr	b	.16	6	0\n"   /* B register (frame pointer) */
		"gpr	l	.16	8	0\n"   /* L register (link/return) */
		"gpr	a	.16	10	0\n"  /* A register (accumulator) */
		"gpr	t	.16	12	0\n"  /* T register */
		"gpr	x	.16	14	0\n"  /* X register (index) */
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
	.version = "1.0.3",
	.bits = 16,
	.esil = true,
	.archinfo = &nd100_archinfo,
	.address_bits = &nd100_address_bits,
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
