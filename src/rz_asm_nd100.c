/*
 * rz_asm_nd100.c - Rizin disassembler plugin for ND-100/ND-110
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "nd100_disasm.h"
#include "moncalls.h"
#include "iodevs.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len < 2) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 0;
		return 0;
	}

	/* Byte order depends on file format:
	 * BPUN files are big-endian, a.out16 files are little-endian.
	 * The bin plugin sets a->big_endian accordingly. */
	uint16_t word;
	if (a->big_endian) {
		word = ((uint16_t)buf[0] << 8) | buf[1];
	} else {
		word = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
	}

	/* CPU mode from Rizin's cpu field */
	int cpu_mode = (a->cpu && strstr(a->cpu, "nd110")) ? CPU_ND110 : CPU_ND100;

	char mnemonic[64];
	nd100_disasm(word, mnemonic, sizeof(mnemonic), cpu_mode);

	/* Annotate MON calls and IOX device registers */
	char annotated[256];
	if ((word & 0xFF00) == 0xD600) {
		/* MON instruction: octal 0153000 range */
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
		/* IOX instruction: device addr in bits 0-10 */
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
	.version = "1.0.0",
	.cpus = "nd100,nd110",
	.desc = "Norsk Data ND-100/ND-110 disassembler",
	.license = "LGPL3",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_BI,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_nd100,
	.version = RZ_VERSION,
};
#endif
