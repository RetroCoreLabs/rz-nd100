/*
 * nd100_disasm.h - ND-100/ND-110 instruction decode API
 *
 * Adapted from nd100x emulator (cpu_disasm.c)
 */

#ifndef ND100_DISASM_H
#define ND100_DISASM_H

#include <stdint.h>

/* CPU mode constants */
#define CPU_ND100   0
#define CPU_ND110   1

/*
 * Disassemble one 16-bit instruction word.
 * Writes mnemonic string into buf (up to bufsz bytes).
 */
void nd100_disasm(uint16_t word, char *buf, int bufsz, int cpu_mode);

/*
 * Returns 1 if instruction is a conditional branch (JAP/JAN/JAZ/JAF/JPC/JNC/JXZ/JXN)
 * or a JMP instruction.
 */
int nd100_is_branch(uint16_t word);

/*
 * Returns the signed 8-bit branch offset for conditional branches,
 * or -256 if the instruction is not a branch.
 */
int nd100_branch_offset(uint16_t word);

#endif /* ND100_DISASM_H */
