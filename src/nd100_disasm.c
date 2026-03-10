/*
 * decode.c - ND-100/ND-110 instruction decoder
 *
 * Adapted from nd100x emulator (cpu_disasm.c)
 *
 * Original copyright:
 * Copyright (c) 2006 Per-Olof Astrom
 * Copyright (c) 2006-2008 Roger Abrahamsson
 * Copyright (c) 2008 Zdravko
 * Copyright (c) 2025 Ronny Hansen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "nd100_disasm.h"

#define BUFSTRSIZE 24
#define BUFSTRSIZE_SMALL 16

static const char *regn[] = {
	"S","D","P","B","L","A","T","X","U0","U1"
};
static const char *regn_w[] = {
	"DS","DD","DP","DB","DL","DA","DT","DX"
};
static const char *intregn_r[] = {
	"PANS","STS","OPR","PGS","PVL","IIC","PID","PIE",
	"CSR","ACTL","ALD","PES","PGC","PEA","16","17"
};
static const char *intregn_w[] = {
	"PANC","STS","LMP","PCR","4","IIE","PID","PIE",
	"CCL","LCIL","UCILR","13","14","15","16","17"
};
static const char *relmode_str[] = {
	"",",B ","I ","I ,B ",",X ",",X ,B ","I ,X ","I ,B ,X "
};
static const char *shtype_str[] = {
	"","ROT ","ZIN ","LIN "
};
static const char *skiptype_str[] = {
	"EQL","GEQ","GRE","MGRE","UEQ","LSS","LST","MLST"
};
static const char *skipregn_dst[] = {
	"0","DD","DP","DB","DL","DA","DT","DX"
};
static const char *skipregn_src[] = {
	"0","SD","SP","SB","SL","SA","ST","SX"
};
static const char *bopstsbit_str[] = {
	"SSPTM","SSTG","SSK","SSZ","SSQ","SSO","SSC","SSM",
	"","","","","","","",""
};
static const char *bop_str[] = {
	"BSET ZRO","BSET ONE","BSET BCM","BSET BAC",
	"BSKP ZRO","BSKP ONE","BSKP BCM","BSKP BAC",
	"BSTC","BSTA","BLDC","BLDA","BANC","BAND","BORC","BORA"
};

/* Forward declarations */
static uint16_t extract_opcode(uint16_t instr, int cpu_mode);
static uint16_t decode_140k(uint16_t instr, int cpu_mode);
static uint16_t decode_150k(uint16_t instr);

void
nd100_disasm(uint16_t operand, char *return_string, int max_len, int cpu_mode)
{
	uint16_t instr;
	char numstr[BUFSTRSIZE_SMALL];
	char deltastr[BUFSTRSIZE_SMALL];
	unsigned char nibble;
	char offset;
	unsigned char delta;
	unsigned char relmode;
	int isneg;
	char opstr[BUFSTRSIZE];

	memset(opstr, 0, sizeof(opstr));

	offset = operand & 0x00ff;
	nibble = operand & 0x000f;
	relmode = (operand & 0x0700) >> 8;
	delta = (operand & 070);

	/* put offset into a string variable in octal with +/- sign */
	((int)offset < 0)
		? (void)snprintf(numstr, sizeof(numstr), "-%o", -(int)offset)
		: (void)snprintf(numstr, sizeof(numstr), "%o", (unsigned char)offset);

	/* ND110 delta offset for some instructions */
	(void)snprintf(deltastr, sizeof(deltastr), "%o", delta);

	instr = extract_opcode(operand, cpu_mode);
	switch (instr) {
	case 0000000: /* STZ */
		(void)snprintf(opstr, BUFSTRSIZE, "STZ %s%s", relmode_str[relmode], numstr);
		break;
	case 0004000: /* STA */
		(void)snprintf(opstr, BUFSTRSIZE, "STA %s%s", relmode_str[relmode], numstr);
		break;
	case 0010000: /* STT */
		(void)snprintf(opstr, BUFSTRSIZE, "STT %s%s", relmode_str[relmode], numstr);
		break;
	case 0014000: /* STX */
		(void)snprintf(opstr, BUFSTRSIZE, "STX %s%s", relmode_str[relmode], numstr);
		break;
	case 0020000: /* STD */
		(void)snprintf(opstr, BUFSTRSIZE, "STD %s%s", relmode_str[relmode], numstr);
		break;
	case 0024000: /* LDD */
		(void)snprintf(opstr, BUFSTRSIZE, "LDD %s%s", relmode_str[relmode], numstr);
		break;
	case 0030000: /* STF */
		(void)snprintf(opstr, BUFSTRSIZE, "STF %s%s", relmode_str[relmode], numstr);
		break;
	case 0034000: /* LDF */
		(void)snprintf(opstr, BUFSTRSIZE, "LDF %s%s", relmode_str[relmode], numstr);
		break;
	case 0040000: /* MIN */
		(void)snprintf(opstr, BUFSTRSIZE, "MIN %s%s", relmode_str[relmode], numstr);
		break;
	case 0044000: /* LDA */
		(void)snprintf(opstr, BUFSTRSIZE, "LDA %s%s", relmode_str[relmode], numstr);
		break;
	case 0050000: /* LDT */
		(void)snprintf(opstr, BUFSTRSIZE, "LDT %s%s", relmode_str[relmode], numstr);
		break;
	case 0054000: /* LDX */
		(void)snprintf(opstr, BUFSTRSIZE, "LDX %s%s", relmode_str[relmode], numstr);
		break;
	case 0060000: /* ADD */
		(void)snprintf(opstr, BUFSTRSIZE, "ADD %s%s", relmode_str[relmode], numstr);
		break;
	case 0064000: /* SUB */
		(void)snprintf(opstr, BUFSTRSIZE, "SUB %s%s", relmode_str[relmode], numstr);
		break;
	case 0070000: /* AND */
		(void)snprintf(opstr, BUFSTRSIZE, "AND %s%s", relmode_str[relmode], numstr);
		break;
	case 0074000: /* ORA */
		(void)snprintf(opstr, BUFSTRSIZE, "ORA %s%s", relmode_str[relmode], numstr);
		break;
	case 0100000: /* FAD */
		(void)snprintf(opstr, BUFSTRSIZE, "FAD %s%s", relmode_str[relmode], numstr);
		break;
	case 0104000: /* FSB */
		(void)snprintf(opstr, BUFSTRSIZE, "FSB %s%s", relmode_str[relmode], numstr);
		break;
	case 0110000: /* FMU */
		(void)snprintf(opstr, BUFSTRSIZE, "FMU %s%s", relmode_str[relmode], numstr);
		break;
	case 0114000: /* FDV */
		(void)snprintf(opstr, BUFSTRSIZE, "FDV %s%s", relmode_str[relmode], numstr);
		break;
	case 0120000: /* MPY */
		(void)snprintf(opstr, BUFSTRSIZE, "MPY %s%s", relmode_str[relmode], numstr);
		break;
	case 0124000: /* JMP */
		(void)snprintf(opstr, BUFSTRSIZE, "JMP %s%s", relmode_str[relmode], numstr);
		break;
	case 0130000: /* JAP */
		(void)snprintf(opstr, BUFSTRSIZE, "JAP %s", numstr);
		break;
	case 0130400: /* JAN */
		(void)snprintf(opstr, BUFSTRSIZE, "JAN %s", numstr);
		break;
	case 0131000: /* JAZ */
		(void)snprintf(opstr, BUFSTRSIZE, "JAZ %s", numstr);
		break;
	case 0131400: /* JAF */
		(void)snprintf(opstr, BUFSTRSIZE, "JAF %s", numstr);
		break;
	case 0132000: /* JPC */
		(void)snprintf(opstr, BUFSTRSIZE, "JPC %s", numstr);
		break;
	case 0132400: /* JNC */
		(void)snprintf(opstr, BUFSTRSIZE, "JNC %s", numstr);
		break;
	case 0133000: /* JXZ */
		(void)snprintf(opstr, BUFSTRSIZE, "JXZ %s", numstr);
		break;
	case 0133400: /* JXN */
		(void)snprintf(opstr, BUFSTRSIZE, "JXN %s", numstr);
		break;
	case 0134000: /* JPL */
		(void)snprintf(opstr, BUFSTRSIZE, "JPL %s%s", relmode_str[relmode], numstr);
		break;
	case 0140000: /* SKP */
		(void)snprintf(opstr, BUFSTRSIZE, "SKP IF %s %s %s",
			skipregn_dst[(operand & 0x0007)],
			skiptype_str[((operand & 0x0700) >> 8)],
			skipregn_src[((operand & 0x0038) >> 3)]);
		break;
	case 0140120: /* ADDD */
		(void)snprintf(opstr, BUFSTRSIZE, "ADDD");
		break;
	case 0140121: /* SUBD */
		(void)snprintf(opstr, BUFSTRSIZE, "SUBD");
		break;
	case 0140122: /* COMD */
		(void)snprintf(opstr, BUFSTRSIZE, "COMD");
		break;
	case 0140123: /* TSET */
		(void)snprintf(opstr, BUFSTRSIZE, "TSET");
		break;
	case 0140124: /* PACK */
		(void)snprintf(opstr, BUFSTRSIZE, "PACK");
		break;
	case 0140125: /* UPACK */
		(void)snprintf(opstr, BUFSTRSIZE, "UPACK");
		break;
	case 0140126: /* SHDE */
		(void)snprintf(opstr, BUFSTRSIZE, "SHDE");
		break;
	case 0140127: /* RDUS */
		(void)snprintf(opstr, BUFSTRSIZE, "RDUS");
		break;
	case 0140130: /* BFILL */
		(void)snprintf(opstr, BUFSTRSIZE, "BFILL");
		break;
	case 0140131: /* MOVB */
		(void)snprintf(opstr, BUFSTRSIZE, "MOVB");
		break;
	case 0140132: /* MOVBF */
		(void)snprintf(opstr, BUFSTRSIZE, "MOVBF");
		break;
	case 0140133: /* VERSN - ND110 specific */
		if (cpu_mode == CPU_ND100)
			break;
		(void)snprintf(opstr, BUFSTRSIZE, "VERSN");
		break;
	case 0140134: /* INIT */
		(void)snprintf(opstr, BUFSTRSIZE, "INIT");
		break;
	case 0140135: /* ENTR */
		(void)snprintf(opstr, BUFSTRSIZE, "ENTR");
		break;
	case 0140136: /* LEAVE */
		(void)snprintf(opstr, BUFSTRSIZE, "LEAVE");
		break;
	case 0140137: /* ELEAV */
		(void)snprintf(opstr, BUFSTRSIZE, "ELEAV");
		break;
	case 0140300: /* SETPT */
		(void)snprintf(opstr, BUFSTRSIZE, "SETPT");
		break;
	case 0140301: /* CLEPT */
		(void)snprintf(opstr, BUFSTRSIZE, "CLEPT");
		break;
	case 0140302: /* CLNREENT */
		(void)snprintf(opstr, BUFSTRSIZE, "CLNREENT");
		break;
	case 0140303: /* CHREENT-PAGES */
		(void)snprintf(opstr, BUFSTRSIZE, "CHREENT-PAGES");
		break;
	case 0140304: /* CLEPU */
		(void)snprintf(opstr, BUFSTRSIZE, "CLEPU");
		break;
	case 0140200: /* USER0 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER0");
		break;
	case 0140500: /* USER1 or ND110 WGLOB */
		if (cpu_mode == CPU_ND100)
			(void)snprintf(opstr, BUFSTRSIZE, "USER1");
		else
			(void)snprintf(opstr, BUFSTRSIZE, "WGLOB");
		break;
	case 0140501: /* RGLOB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "RGLOB");
		break;
	case 0140502: /* INSPL - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "INSPL");
		break;
	case 0140503: /* REMPL - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "REMPL");
		break;
	case 0140504: /* CNREK - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "CNREK");
		break;
	case 0140505: /* CLPT  - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "CLPT");
		break;
	case 0140506: /* ENPT  - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "ENPT");
		break;
	case 0140507: /* REPT  - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "REPT");
		break;
	case 0140510: /* LBIT  - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "LBIT");
		break;
	case 0140513: /* SBITP - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SBITP");
		break;
	case 0140514: /* LBYTP - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "LBYTP");
		break;
	case 0140515: /* SBYTP - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SBYTP");
		break;
	case 0140516: /* TSETP - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "TSETP");
		break;
	case 0140517: /* RDUSP - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "RDUSP");
		break;
	case 0140600: /* EXR */
		(void)snprintf(opstr, BUFSTRSIZE, "EXR %s",
			skipregn_src[((operand & 0x0038) >> 3)]);
		break;
	case 0140700: /* USER2 or ND110 LASB */
		if (cpu_mode == CPU_ND100)
			(void)snprintf(opstr, BUFSTRSIZE, "USER2");
		else
			(void)snprintf(opstr, BUFSTRSIZE, "LASB %s", deltastr);
		break;
	case 0140701: /* SASB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SASB %s", deltastr);
		break;
	case 0140702: /* LACB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "LACB %s", deltastr);
		break;
	case 0140703: /* SACB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SACB %s", deltastr);
		break;
	case 0140704: /* LXSB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "LXSB %s", deltastr);
		break;
	case 0140705: /* LXCB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "LXCB %s", deltastr);
		break;
	case 0140706: /* SZSB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SZSB %s", deltastr);
		break;
	case 0140707: /* SZCB - ND110 Specific */
		(void)snprintf(opstr, BUFSTRSIZE, "SZCB %s", deltastr);
		break;
	case 0141100: /* USER3 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER3");
		break;
	case 0141200: /* RMPY */
		(void)snprintf(opstr, BUFSTRSIZE, "RMPY %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0141300: /* USER4 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER4");
		break;
	case 0141500: /* USER5 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER5");
		break;
	case 0141600: /* RDIV */
		(void)snprintf(opstr, BUFSTRSIZE, "RDIV %s",
			skipregn_src[((operand & 0x0038) >> 3)]);
		break;
	case 0141700: /* USER6 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER6");
		break;
	case 0142100: /* USER7 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER7");
		break;
	case 0142200: /* LBYT */
		(void)snprintf(opstr, BUFSTRSIZE, "LBYT");
		break;
	case 0142300: /* USER8 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER8");
		break;
	case 0142500: /* USER9 */
		(void)snprintf(opstr, BUFSTRSIZE, "USER9");
		break;
	case 0142600: /* SBYT */
		(void)snprintf(opstr, BUFSTRSIZE, "SBYT");
		break;
	case 0142700: /* GECO */
		(void)snprintf(opstr, BUFSTRSIZE, "GECO");
		break;
	case 0143100: /* MOVEW */
		(void)snprintf(opstr, BUFSTRSIZE, "MOVEW");
		break;
	case 0143200: /* MIX3 */
		(void)snprintf(opstr, BUFSTRSIZE, "MIX3");
		break;
	case 0143300: /* LDATX */
		(void)snprintf(opstr, BUFSTRSIZE, "LDATX");
		break;
	case 0143301: /* LDXTX */
		(void)snprintf(opstr, BUFSTRSIZE, "LDXTX");
		break;
	case 0143302: /* LDDTX */
		(void)snprintf(opstr, BUFSTRSIZE, "LDDTX");
		break;
	case 0143303: /* LDBTX */
		(void)snprintf(opstr, BUFSTRSIZE, "LDBTX");
		break;
	case 0143304: /* STATX */
		(void)snprintf(opstr, BUFSTRSIZE, "STATX");
		break;
	case 0143305: /* STZTX */
		(void)snprintf(opstr, BUFSTRSIZE, "STZTX");
		break;
	case 0143306: /* STDTX */
		(void)snprintf(opstr, BUFSTRSIZE, "STDTX");
		break;
	case 0143500: /* LWCS */
		(void)snprintf(opstr, BUFSTRSIZE, "LWCS");
		break;
	case 0143604: /* IDENT PL10 */
		(void)snprintf(opstr, BUFSTRSIZE, "IDENT PL10");
		break;
	case 0143611: /* IDENT PL11 */
		(void)snprintf(opstr, BUFSTRSIZE, "IDENT PL11");
		break;
	case 0143622: /* IDENT PL12 */
		(void)snprintf(opstr, BUFSTRSIZE, "IDENT PL12");
		break;
	case 0143643: /* IDENT PL13 */
		(void)snprintf(opstr, BUFSTRSIZE, "IDENT PL13");
		break;
	case 0144000: /* SWAP */
		(void)snprintf(opstr, BUFSTRSIZE, "SWAP %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144100: /* SWAP CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "SWAP CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144200: /* SWAP CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "SWAP CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144300: /* SWAP CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "SWAP CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144400: /* RAND */
		(void)snprintf(opstr, BUFSTRSIZE, "RAND %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144500: /* RAND CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RAND CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144600: /* RAND CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "RAND CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0144700: /* RAND CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RAND CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145000: /* REXO */
		(void)snprintf(opstr, BUFSTRSIZE, "REXO %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145100: /* REXO CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "REXO CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145200: /* REXO CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "REXO CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145300: /* REXO CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "REXO CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145400: /* RORA */
		(void)snprintf(opstr, BUFSTRSIZE, "RORA %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145500: /* RORA CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RORA CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145600: /* RORA CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "RORA CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0145700: /* RORA CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RORA CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146000: /* RADD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146100: /* RADD CLD */
		if (operand == 0146142)
			snprintf(opstr, BUFSTRSIZE, "EXIT");
		else
			(void)snprintf(opstr, BUFSTRSIZE, "RADD CLD %s %s",
				skipregn_src[((operand & 0x0038) >> 3)],
				skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146200: /* RADD CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146300: /* RADD CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146400: /* RADD AD1 */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD AD1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146500: /* RADD AD1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD AD1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146600: /* RSUB */
		(void)snprintf(opstr, BUFSTRSIZE, "RSUB %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0146700: /* RADD AD1 CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD AD1 CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0147000: /* RADD ADC */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD ADC %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0147100: /* RADD ADC CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD ADC CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0147200: /* RADD ADC CM1 */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD ADC CM1 %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0147300: /* RADD ADC CM1 CLD */
		(void)snprintf(opstr, BUFSTRSIZE, "RADD ADC CM1 CLD %s %s",
			skipregn_src[((operand & 0x0038) >> 3)],
			skipregn_dst[(operand & 0x0007)]);
		break;
	case 0147400: /* NOOP */
	case 0147500:
	case 0147600:
	case 0147700:
		(void)snprintf(opstr, BUFSTRSIZE, "ROP NOOP");
		break;
	case 0150000: /* TRA */
		(void)snprintf(opstr, BUFSTRSIZE, "TRA %s", intregn_r[nibble]);
		break;
	case 0150100: /* TRR */
		(void)snprintf(opstr, BUFSTRSIZE, "TRR %s", intregn_w[nibble]);
		break;
	case 0150200: /* MCL */
		(void)snprintf(opstr, BUFSTRSIZE, "MCL %s", intregn_w[nibble]);
		break;
	case 0150300: /* MST */
		(void)snprintf(opstr, BUFSTRSIZE, "MST %s", intregn_w[nibble]);
		break;
	case 0150400: /* OPCOM */
		(void)snprintf(opstr, BUFSTRSIZE, "OPCOM");
		break;
	case 0150401: /* IOF */
		(void)snprintf(opstr, BUFSTRSIZE, "IOF");
		break;
	case 0150402: /* ION */
		(void)snprintf(opstr, BUFSTRSIZE, "ION");
		break;
	case 0150404: /* POF */
		(void)snprintf(opstr, BUFSTRSIZE, "POF");
		break;
	case 0150405: /* PIOF */
		(void)snprintf(opstr, BUFSTRSIZE, "PIOF");
		break;
	case 0150406: /* SEX */
		(void)snprintf(opstr, BUFSTRSIZE, "SEX");
		break;
	case 0150407: /* REX */
		(void)snprintf(opstr, BUFSTRSIZE, "REX");
		break;
	case 0150410: /* PON */
		(void)snprintf(opstr, BUFSTRSIZE, "PON");
		break;
	case 0150412: /* PION */
		(void)snprintf(opstr, BUFSTRSIZE, "PION");
		break;
	case 0150415: /* IOXT */
		(void)snprintf(opstr, BUFSTRSIZE, "IOXT");
		break;
	case 0150416: /* EXAM */
		(void)snprintf(opstr, BUFSTRSIZE, "EXAM");
		break;
	case 0150417: /* DEPO */
		(void)snprintf(opstr, BUFSTRSIZE, "DEPO");
		break;
	case 0151000: /* WAIT */
		(void)snprintf(opstr, BUFSTRSIZE, "WAIT");
		break;
	case 0151400: /* NLZ */
		(void)snprintf(opstr, BUFSTRSIZE, "NLZ %s", numstr);
		break;
	case 0152000: /* DNZ */
		(void)snprintf(opstr, BUFSTRSIZE, "DNZ %s", numstr);
		break;
	case 0152400: /* SRB */
		(void)snprintf(opstr, BUFSTRSIZE, "SRB %o", (operand & 0x0078));
		break;
	case 0152600: /* LRB */
		(void)snprintf(opstr, BUFSTRSIZE, "LRB %o", (operand & 0x0078) >> 3);
		break;
	case 0153000: /* MON */
		(void)snprintf(opstr, BUFSTRSIZE, "MON %o", (operand & 0x00ff));
		break;
	case 0153400: /* IRW */
		(void)snprintf(opstr, BUFSTRSIZE, "IRW %o %s",
			(operand & 0x0078), regn_w[(operand & 0x0007)]);
		break;
	case 0153600: /* IRR */
		(void)snprintf(opstr, BUFSTRSIZE, "IRR %o %s",
			(operand & 0x0078), regn_w[(operand & 0x0007)]);
		break;
	case 0154000: /* SHT */
		isneg = ((operand & 0x0020) >> 5) ? 1 : 0;
		offset = (isneg)
			? (~((operand & 0x003F) | 0xFFC0) + 1)
			: (operand & 0x003F);
		(isneg)
			? (void)snprintf(numstr, sizeof(numstr), "SHR %o", (unsigned char)offset)
			: (void)snprintf(numstr, sizeof(numstr), "%o", (unsigned char)offset);
		(void)snprintf(opstr, BUFSTRSIZE, "SHT %s%s",
			shtype_str[((operand & 0x0600) >> 9)], numstr);
		break;
	case 0154200: /* SHD */
		isneg = ((operand & 0x0020) >> 5) ? 1 : 0;
		offset = (isneg)
			? (~((operand & 0x003F) | 0xFFC0) + 1)
			: (operand & 0x003F);
		(isneg)
			? (void)snprintf(numstr, sizeof(numstr), "SHR %o", (unsigned char)offset)
			: (void)snprintf(numstr, sizeof(numstr), "%o", (unsigned char)offset);
		(void)snprintf(opstr, BUFSTRSIZE, "SHD %s%s",
			shtype_str[((operand & 0x0600) >> 9)], numstr);
		break;
	case 0154400: /* SHA */
		isneg = ((operand & 0x0020) >> 5) ? 1 : 0;
		offset = (isneg)
			? (~((operand & 0x003F) | 0xFFC0) + 1)
			: (operand & 0x003F);
		(isneg)
			? (void)snprintf(numstr, sizeof(numstr), "SHR %o", (unsigned char)offset)
			: (void)snprintf(numstr, sizeof(numstr), "%o", (unsigned char)offset);
		(void)snprintf(opstr, BUFSTRSIZE, "SHA %s%s",
			shtype_str[((operand & 0x0600) >> 9)], numstr);
		break;
	case 0154600: /* SAD */
		isneg = ((operand & 0x0020) >> 5) ? 1 : 0;
		offset = (isneg)
			? (~((operand & 0x003F) | 0xFFC0) + 1)
			: (operand & 0x003F);
		(isneg)
			? (void)snprintf(numstr, sizeof(numstr), "SHR %o", (unsigned char)offset)
			: (void)snprintf(numstr, sizeof(numstr), "%o", (unsigned char)offset);
		(void)snprintf(opstr, BUFSTRSIZE, "SAD %s%s",
			shtype_str[((operand & 0x0600) >> 9)], numstr);
		break;
	case 0160000: /* IOT */
		(void)snprintf(opstr, BUFSTRSIZE, "IOT %o", (operand & 0x07ff));
		break;
	case 0164000: /* IOX */
		(void)snprintf(opstr, BUFSTRSIZE, "IOX %o", (operand & 0x07ff));
		break;
	case 0170000: /* SAB */
		(void)snprintf(opstr, BUFSTRSIZE, "SAB %s", numstr);
		break;
	case 0170400: /* SAA */
		(void)snprintf(opstr, BUFSTRSIZE, "SAA %s", numstr);
		break;
	case 0171000: /* SAT */
		(void)snprintf(opstr, BUFSTRSIZE, "SAT %s", numstr);
		break;
	case 0171400: /* SAX */
		(void)snprintf(opstr, BUFSTRSIZE, "SAX %s", numstr);
		break;
	case 0172000: /* AAB */
		(void)snprintf(opstr, BUFSTRSIZE, "AAB %s", numstr);
		break;
	case 0172400: /* AAA */
		(void)snprintf(opstr, BUFSTRSIZE, "AAA %s", numstr);
		break;
	case 0173000: /* AAT */
		(void)snprintf(opstr, BUFSTRSIZE, "AAT %s", numstr);
		break;
	case 0173400: /* AAX */
		(void)snprintf(opstr, BUFSTRSIZE, "AAX %s", numstr);
		break;
	case 0174000: /* BSET ZRO */
	case 0174200: /* BSET ONE */
	case 0174400: /* BSET BCM */
	case 0174600: /* BSET BAC */
	case 0175000: /* BSKP ZRO */
	case 0175200: /* BSKP ONE */
	case 0175400: /* BSKP BCM */
	case 0175600: /* BSKP BAC */
	case 0176000: /* BSTC */
	case 0176200: /* BSTA */
	case 0176400: /* BLDC */
	case 0176600: /* BLDA */
	case 0177000: /* BANC */
	case 0177200: /* BAND */
	case 0177400: /* BORC */
	case 0177600: /* BORA */
		if (!(operand & 0x0007))
			(void)snprintf(opstr, BUFSTRSIZE, "%s %s",
				bop_str[((operand & 0x0780) >> 7)],
				bopstsbit_str[((operand & 0x0078) >> 3)]);
		else
			(void)snprintf(opstr, BUFSTRSIZE, "%s %o D%s",
				bop_str[((operand & 0x0780) >> 7)],
				(int)(operand & 0x0078),
				regn[(operand & 0x0007)]);
		break;
	default: /* UNDEF */
		(void)snprintf(opstr, BUFSTRSIZE, "UNDEF");
		break;
	}

	snprintf(return_string, max_len, "%s", opstr);
}

int
nd100_is_branch(uint16_t word)
{
	uint16_t top5 = word & 0xF800;

	/* JMP 0124000 */
	if (top5 == 0124000)
		return 1;
	/* JPL 0134000 */
	if (top5 == 0134000)
		return 1;
	/* JAP/JAN/JAZ/JAF/JPC/JNC/JXZ/JXN: 0130000-0133777 */
	if (top5 == 0130000)
		return 1;
	return 0;
}

int
nd100_branch_offset(uint16_t word)
{
	int off;

	if (!nd100_is_branch(word))
		return -256;

	off = (signed char)(word & 0xFF);
	return off;
}

/*
 * Mask out instruction opcode from parameters.
 */
static uint16_t
extract_opcode(uint16_t instr, int cpu_mode)
{
	switch (instr & (0xFFFF << 11)) {
	case 0130000: /* JAP, JAN, JAZ, JAF, JPC, JNC, JXZ, JXN */
		return (instr & (0xFFFF << 8));
	case 0140000:
		if (0 == (instr & (0x03 << 6))) /* SKIP Instruction */
			return 0140000;
		else
			return (decode_140k(instr, cpu_mode));
	case 0150000:
		return (decode_150k(instr));
	case 0144000: /* ROP Register operations */
		return instr & (0xFFFF << 6);
	case 0154000: /* Shift Instruction */
		return instr & ((0xFFFF << 11) | (0x03 << 7));
	case 0170000: /* Argument Instructions */
		return instr & (0xFFFF << 8);
	case 0174000: /* Bit Operation Instructions */
		return instr & (0xFFFF << 7);
	default: /* Memory Reference Instructions & IOX */
		return instr & (0xFFFF << 11);
	}
	return instr;
}

static uint16_t
decode_140k(uint16_t instr, int cpu_mode)
{
	switch (instr & 0xFFFF) {
	case 0140120: /* ADDD */
	case 0140121: /* SUBD */
	case 0140122: /* COMD */
	case 0140123: /* TSET */
	case 0140124: /* PACK */
	case 0140125: /* UPACK */
	case 0140126: /* SHDE */
	case 0140127: /* RDUS */
	case 0140130: /* BFILL */
	case 0140131: /* MOVB */
	case 0140132: /* MOVBF */
		return instr;
	case 0140133: /* VERSN - ND110 specific */
		if (cpu_mode == CPU_ND110)
			return instr;
		else
			break;
	case 0140134: /* INIT */
	case 0140135: /* ENTR */
	case 0140136: /* LEAVE */
	case 0140137: /* ELEAV */
	case 0140300: /* SETPT */
	case 0140301: /* CLEPT */
	case 0140302: /* CLNREENT */
	case 0140303: /* CHREENT-PAGES */
	case 0140304: /* CLEPU */
	case 0143500: /* LWCS */
	case 0143604: /* IDENT PL10 */
	case 0143611: /* IDENT PL11 */
	case 0143622: /* IDENT PL12 */
	case 0143643: /* IDENT PL13 */
		return instr;
	default:
		break;
	}
	switch (instr & (0xFFFF << 6)) {
	case 0140200: /* USER0 */
		return instr & (0xFFFF << 6);
	case 0140500: /* USER1 or ND110 instructions */
		if (cpu_mode == CPU_ND100)
			return instr & (0xFFFF << 6);
		else switch (instr & 0xFFFF) {
			case 0140500: /* WGLOB */
			case 0140501: /* RGLOB */
			case 0140502: /* INSPL */
			case 0140503: /* REMPL */
			case 0140504: /* CNREK */
			case 0140505: /* CLPT */
			case 0140506: /* ENPT */
			case 0140507: /* REPT */
			case 0140510: /* LBIT */
			case 0140513: /* SBITP */
			case 0140514: /* LBYTP */
			case 0140515: /* SBYTP */
			case 0140516: /* TSETP */
			case 0140517: /* RDUSP */
				return instr;
			default:
				break;
		}
		break;
	case 0140600: /* EXR */
		return instr & (0xFFFF << 6);
	case 0140700: /* USER2 or ND110 instructions */
		if (cpu_mode == CPU_ND100)
			return instr & (0xFFFF << 6);
		else switch (instr & 0xFFC7) {
			case 0140700: /* LASB */
			case 0140701: /* SASB */
			case 0140702: /* LACB */
			case 0140703: /* SACB */
			case 0140704: /* LXSB */
			case 0140705: /* LXCB */
			case 0140706: /* SZSB */
			case 0140707: /* SZCB */
				return (instr & 0xFFC7);
			default:
				break;
		}
		break;
	case 0141100: /* USER3 */
	case 0141200: /* RMPY */
	case 0141300: /* USER4 */
	case 0141500: /* USER5 */
	case 0141600: /* RDIV */
	case 0141700: /* USER6 */
	case 0142100: /* USER7 */
	case 0142200: /* LBYT */
	case 0142300: /* USER8 */
	case 0142500: /* USER9 */
	case 0142600: /* SBYT */
	case 0142700: /* GECO */
	case 0143100: /* MOVEW */
	case 0143200: /* MIX3 */
		return instr & (0xFFFF << 6);
	default:
		break;
	}
	switch (instr & 0xFFC7) {
	case 0143300: /* LDATX */
	case 0143301: /* LDXTX */
	case 0143302: /* LDDTX */
	case 0143303: /* LDBTX */
	case 0143304: /* STATX */
	case 0143305: /* STZTX */
	case 0143306: /* STDTX */
		return (instr & 0xFFC7);
	default:
		break;
	}
	return instr;
}

static uint16_t
decode_150k(uint16_t instr)
{
	switch (instr & 0xFFFF) {
	case 0150400: /* OPCOM */
	case 0150401: /* IOF */
	case 0150402: /* ION */
	case 0150404: /* POF */
	case 0150405: /* PIOF */
	case 0150406: /* SEX */
	case 0150407: /* REX */
	case 0150410: /* PON */
	case 0150412: /* PION */
	case 0150415: /* IOXT */
	case 0150416: /* EXAM */
	case 0150417: /* DEPO */
		return instr;
	default:
		break;
	}
	switch (instr & (0xFFFF << 8)) {
	case 0151000: /* WAIT */
	case 0151400: /* NLZ */
	case 0152000: /* DNZ */
	case 0153000: /* MON */
		return (uint16_t)(instr & (0xFFFF << 8));
	default:
		break;
	}
	switch (instr & (0xFFFF << 7)) {
	case 0152400: /* SRB */
	case 0152600: /* LRB */
	case 0153400: /* IRW */
	case 0153600: /* IRR */
		return instr & (0xFFFF << 7);
	default:
		break;
	}
	switch (instr & (0xFFFF << 6)) {
	case 0150000: /* TRA */
	case 0150100: /* TRR */
	case 0150200: /* MCL */
	case 0150300: /* MST */
		return instr & (0xFFFF << 6);
	default:
		break;
	}
	return instr;
}
