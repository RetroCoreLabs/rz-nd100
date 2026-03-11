/*
 * rz_bin_aout16.c - Rizin binary loader for ND-100 a.out16 object files
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * a.out16 format (ND-100):
 *   Header (16 bytes, little-endian):
 *     magic(2) text_size(2) data_size(2) bss_size(2)
 *     syms_size(2) entry(2) zp_size(2) flag(2)
 *   Followed by: zp | text | data | zp_reloc | text_reloc | data_reloc | symbols | strings
 *   All sizes are in 16-bit words.
 *   Symbol types: N_TEXT=0x02, N_DATA=0x03, etc. (assembler encoding)
 */

#include <rz_bin.h>
#include <rz_lib.h>

#define AOUT16_MAGIC   0407   /* octal 0407 */
#define AOUT16_HDRSZ   16    /* header size in bytes */

/* Symbol type constants */
#define N_UNDF  0x00
#define N_ABS   0x01
#define N_TEXT  0x02
#define N_DATA  0x03
#define N_BSS   0x04
#define N_ZREL  0x05
#define N_EXT   0x20
#define N_TYPE_MASK 0x1F

struct aout16_sym {
	uint32_t strx;
	uint16_t type;
	uint16_t value;
};

struct aout16_obj {
	uint16_t a_magic;
	uint16_t a_text;     /* text size in words */
	uint16_t a_data;     /* data size in words */
	uint16_t a_bss;      /* bss size in words */
	uint16_t a_syms;     /* symbol table size in words */
	uint16_t a_entry;    /* entry point (word address) */
	uint16_t a_zp;       /* zero page size in words */
	uint16_t a_flag;     /* nonzero = reloc stripped */

	ut64 off_text;       /* file offset of text segment */
	ut64 off_data;       /* file offset of data segment */

	struct aout16_sym *syms;
	int nsyms;
	char *strtab;
	uint32_t strtab_size;
};

static uint16_t read_le16(RzBuffer *buf, ut64 off) {
	ut8 b[2];
	if (rz_buf_read_at(buf, off, b, 2) != 2) {
		return 0;
	}
	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t read_le32(RzBuffer *buf, ut64 off) {
	ut8 b[4];
	if (rz_buf_read_at(buf, off, b, 4) != 4) {
		return 0;
	}
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static struct aout16_obj *aout16_parse(RzBuffer *buf) {
	struct aout16_obj *obj;
	ut64 off_syms, off_str;
	int i;

	if (rz_buf_size(buf) < AOUT16_HDRSZ) {
		return NULL;
	}

	obj = RZ_NEW0(struct aout16_obj);
	if (!obj) {
		return NULL;
	}

	obj->a_magic = read_le16(buf, 0);
	obj->a_text  = read_le16(buf, 2);
	obj->a_data  = read_le16(buf, 4);
	obj->a_bss   = read_le16(buf, 6);
	obj->a_syms  = read_le16(buf, 8);
	obj->a_entry = read_le16(buf, 10);
	obj->a_zp    = read_le16(buf, 12);
	obj->a_flag  = read_le16(buf, 14);

	if (obj->a_magic != AOUT16_MAGIC) {
		free(obj);
		return NULL;
	}

	obj->off_text = AOUT16_HDRSZ + (ut64)obj->a_zp * 2;
	obj->off_data = obj->off_text + (ut64)obj->a_text * 2;

	/* Symbol table */
	obj->nsyms = obj->a_syms / 4; /* each symbol is 4 words = 8 bytes */

	/* File layout: header | zp | text | data | zp_reloc | text_reloc | data_reloc | syms | strings */
	off_syms = obj->off_data + (ut64)obj->a_data * 2 +
	           (ut64)obj->a_zp * 2 +    /* zp relocs */
	           (ut64)obj->a_text * 2 +   /* text relocs */
	           (ut64)obj->a_data * 2;    /* data relocs */

	if (obj->a_flag) {
		/* Reloc stripped: syms right after data */
		off_syms = obj->off_data + (ut64)obj->a_data * 2;
	}

	off_str = off_syms + (ut64)obj->a_syms * 2;

	if (obj->nsyms > 0 && off_syms + (ut64)obj->a_syms * 2 <= rz_buf_size(buf)) {
		obj->syms = RZ_NEWS0(struct aout16_sym, obj->nsyms);
		if (obj->syms) {
			for (i = 0; i < obj->nsyms; i++) {
				ut64 soff = off_syms + (ut64)i * 8;
				obj->syms[i].strx = read_le32(buf, soff);
				obj->syms[i].type = read_le16(buf, soff + 4);
				obj->syms[i].value = read_le16(buf, soff + 6);
			}
		}

		/* String table: first 4 bytes are the size */
		if (off_str + 4 <= rz_buf_size(buf)) {
			obj->strtab_size = read_le32(buf, off_str);
			if (obj->strtab_size >= 4 && off_str + obj->strtab_size <= rz_buf_size(buf)) {
				obj->strtab = malloc(obj->strtab_size);
				if (obj->strtab) {
					rz_buf_read_at(buf, off_str, (ut8 *)obj->strtab, obj->strtab_size);
				}
			}
		}
	}

	return obj;
}

static const char *aout16_sym_name(struct aout16_obj *obj, int idx) {
	if (idx < 0 || idx >= obj->nsyms || !obj->syms) {
		return NULL;
	}
	uint32_t strx = obj->syms[idx].strx;
	if (!obj->strtab || strx >= obj->strtab_size) {
		return NULL;
	}
	return obj->strtab + strx;
}

static bool aout16_check_buffer(RzBuffer *buf) {
	ut8 b[2];
	uint16_t magic;

	if (rz_buf_read_at(buf, 0, b, 2) != 2) {
		return false;
	}
	magic = (uint16_t)b[0] | ((uint16_t)b[1] << 8);
	return magic == AOUT16_MAGIC;
}

static bool aout16_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	struct aout16_obj *aobj = aout16_parse(buf);
	if (!aobj) {
		return false;
	}
	obj->bin_obj = aobj;
	return true;
}

static void aout16_destroy(RzBinFile *bf) {
	struct aout16_obj *obj;

	if (!bf || !bf->o) {
		return;
	}
	obj = bf->o->bin_obj;
	if (obj) {
		free(obj->syms);
		free(obj->strtab);
		free(obj);
	}
	bf->o->bin_obj = NULL;
}

static ut64 aout16_baddr(RzBinFile *bf) {
	struct aout16_obj *obj;

	if (!bf || !bf->o) {
		return 0;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return 0;
	}
	/* Text base = entry point word address * 2 bytes/word */
	return (ut64)obj->a_entry * 2;
}

static RzPVector *aout16_entries(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *entries;
	RzBinAddr *entry;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	entries = rz_pvector_new(free);
	if (!entries) {
		return NULL;
	}

	entry = RZ_NEW0(RzBinAddr);
	if (!entry) {
		rz_pvector_free(entries);
		return NULL;
	}

	/* Entry point: word address -> byte address
	 * paddr is at the start of the text segment in the file */
	entry->vaddr = (ut64)obj->a_entry * 2;
	entry->paddr = obj->off_text;
	entry->bits = 16;
	rz_pvector_push(entries, entry);

	return entries;
}

static RzPVector *aout16_maps(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *maps;
	RzBinMap *map;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	maps = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!maps) {
		return NULL;
	}

	ut64 text_vaddr = (ut64)obj->a_entry * 2;

	/* Text segment */
	if (obj->a_text > 0) {
		map = RZ_NEW0(RzBinMap);
		if (map) {
			map->paddr = obj->off_text;
			map->psize = (ut64)obj->a_text * 2;
			map->vaddr = text_vaddr;
			map->vsize = (ut64)obj->a_text * 2;
			map->perm = RZ_PERM_RX;
			map->name = rz_str_dup("text");
			rz_pvector_push(maps, map);
		}
	}

	/* Data segment */
	if (obj->a_data > 0) {
		map = RZ_NEW0(RzBinMap);
		if (map) {
			map->paddr = obj->off_data;
			map->psize = (ut64)obj->a_data * 2;
			map->vaddr = text_vaddr + (ut64)obj->a_text * 2;
			map->vsize = (ut64)obj->a_data * 2;
			map->perm = RZ_PERM_RW;
			map->name = rz_str_dup("data");
			rz_pvector_push(maps, map);
		}
	}

	/* BSS segment (no file backing) */
	if (obj->a_bss > 0) {
		map = RZ_NEW0(RzBinMap);
		if (map) {
			map->paddr = 0;
			map->psize = 0;
			map->vaddr = text_vaddr + (ut64)(obj->a_text + obj->a_data) * 2;
			map->vsize = (ut64)obj->a_bss * 2;
			map->perm = RZ_PERM_RW;
			map->name = rz_str_dup("bss");
			rz_pvector_push(maps, map);
		}
	}

	return maps;
}

static RzPVector *aout16_sections(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *sections;
	RzBinSection *sec;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	ut64 text_vaddr = (ut64)obj->a_entry * 2;

	sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}

	/* Text segment */
	if (obj->a_text > 0) {
		sec = RZ_NEW0(RzBinSection);
		if (sec) {
			sec->name = rz_str_dup("text");
			sec->paddr = obj->off_text;
			sec->size = (ut64)obj->a_text * 2;
			sec->vaddr = text_vaddr;
			sec->vsize = (ut64)obj->a_text * 2;
			sec->perm = RZ_PERM_RX;
			sec->bits = 16;
			rz_pvector_push(sections, sec);
		}
	}

	/* Data segment */
	if (obj->a_data > 0) {
		sec = RZ_NEW0(RzBinSection);
		if (sec) {
			sec->name = rz_str_dup("data");
			sec->paddr = obj->off_data;
			sec->size = (ut64)obj->a_data * 2;
			sec->vaddr = text_vaddr + (ut64)obj->a_text * 2;
			sec->vsize = (ut64)obj->a_data * 2;
			sec->perm = RZ_PERM_RW;
			sec->bits = 16;
			sec->is_data = true;
			rz_pvector_push(sections, sec);
		}
	}

	/* BSS segment */
	if (obj->a_bss > 0) {
		sec = RZ_NEW0(RzBinSection);
		if (sec) {
			sec->name = rz_str_dup("bss");
			sec->paddr = 0;
			sec->size = 0;
			sec->vaddr = text_vaddr + (ut64)(obj->a_text + obj->a_data) * 2;
			sec->vsize = (ut64)obj->a_bss * 2;
			sec->perm = RZ_PERM_RW;
			sec->bits = 16;
			sec->is_data = true;
			rz_pvector_push(sections, sec);
		}
	}

	return sections;
}

static RzPVector *aout16_symbols(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *symbols;
	int i;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj || !obj->syms) {
		return NULL;
	}

	symbols = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}

	for (i = 0; i < obj->nsyms; i++) {
		const char *name = aout16_sym_name(obj, i);
		uint16_t stype = obj->syms[i].type;
		uint16_t sval = obj->syms[i].value;
		RzBinSymbol *sym;
		uint16_t section;

		if (!name || name[0] == '\0') {
			continue;
		}

		/* Skip undefined symbols */
		section = stype & N_TYPE_MASK;
		if (section == N_UNDF && !(stype & N_EXT)) {
			continue;
		}

		sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			continue;
		}

		sym->name = rz_str_dup(name);
		sym->size = 2; /* one word */
		sym->bits = 16;

		/* Symbol values are absolute word addresses.
		 * vaddr = value * 2 (word -> byte address)
		 * paddr = file offset based on segment position */
		switch (section) {
		case N_TEXT:
			sym->vaddr = (ut64)sval * 2;
			sym->paddr = obj->off_text + (ut64)(sval - obj->a_entry) * 2;
			sym->type = "FUNC";
			break;
		case N_DATA:
			sym->vaddr = (ut64)sval * 2;
			sym->paddr = obj->off_data + (ut64)(sval - obj->a_entry - obj->a_text) * 2;
			sym->type = "OBJ";
			break;
		case N_BSS:
			sym->vaddr = (ut64)sval * 2;
			sym->paddr = 0;
			sym->type = "OBJ";
			break;
		case N_ABS:
			sym->vaddr = (ut64)sval * 2;
			sym->paddr = 0;
			sym->type = "ABS";
			break;
		default:
			sym->vaddr = (ut64)sval * 2;
			sym->paddr = 0;
			sym->type = "NOTYPE";
			break;
		}

		sym->bind = (stype & N_EXT) ? "GLOBAL" : "LOCAL";
		sym->is_imported = (section == N_UNDF && (stype & N_EXT));
		sym->ordinal = i;
		rz_pvector_push(symbols, sym);
	}

	return symbols;
}

static RzPVector *aout16_imports(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *imports;
	int i;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj || !obj->syms) {
		return NULL;
	}

	imports = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!imports) {
		return NULL;
	}

	for (i = 0; i < obj->nsyms; i++) {
		const char *name;
		uint16_t stype = obj->syms[i].type;
		uint16_t section = stype & N_TYPE_MASK;
		RzBinImport *imp;

		/* Imports are undefined external symbols */
		if (section != N_UNDF || !(stype & N_EXT)) {
			continue;
		}

		name = aout16_sym_name(obj, i);
		if (!name || name[0] == '\0') {
			continue;
		}

		imp = RZ_NEW0(RzBinImport);
		if (!imp) {
			continue;
		}

		imp->name = rz_str_dup(name);
		imp->bind = "GLOBAL";
		imp->type = "FUNC";
		imp->ordinal = i;
		rz_pvector_push(imports, imp);
	}

	return imports;
}

/*
 * Relocation word format (one per text/data word, parallel array):
 *   bit 0:     REL_8 flag (8-bit displacement)
 *   bits 1-3:  relocation type
 *   bits 4-15: symbol number (for REL_UNDEXT only)
 */
#define REL_8       001
#define REL_ZP      002
#define REL_TEXT    004
#define REL_DATA    006
#define REL_BSS     010
#define REL_ABS     012
#define REL_UNDEXT  014
#define REL_BPTR    016
#define RELMSK      016

static RzPVector *aout16_relocs(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *relocs;
	int i;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	/* Relocations only present when not stripped */
	if (obj->a_flag) {
		return NULL;
	}

	relocs = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	if (!relocs) {
		return NULL;
	}

	RzBuffer *buf = bf->buf;
	ut64 text_vaddr = (ut64)obj->a_entry * 2;
	ut64 data_vaddr = text_vaddr + (ut64)obj->a_text * 2;

	/* Reloc sections follow: zp | text | data | zp_reloc | text_reloc | data_reloc */
	ut64 off_zp_reloc = obj->off_data + (ut64)obj->a_data * 2;
	ut64 off_text_reloc = off_zp_reloc + (ut64)obj->a_zp * 2;
	ut64 off_data_reloc = off_text_reloc + (ut64)obj->a_text * 2;

	/* Process text relocations */
	for (i = 0; i < (int)obj->a_text; i++) {
		uint16_t relword = read_le16(buf, off_text_reloc + (ut64)i * 2);
		uint16_t rtype;
		RzBinReloc *rel;

		if (relword == 0) {
			continue;
		}

		rtype = relword & RELMSK;
		if (rtype == 0 || rtype == REL_ABS) {
			continue;
		}

		rel = RZ_NEW0(RzBinReloc);
		if (!rel) {
			continue;
		}

		rel->vaddr = text_vaddr + (ut64)i * 2;
		rel->paddr = obj->off_text + (ut64)i * 2;
		rel->additive = true;

		if (relword & REL_8) {
			rel->type = RZ_BIN_RELOC_8;
		} else {
			rel->type = RZ_BIN_RELOC_16;
		}

		if (rtype == REL_UNDEXT) {
			int symnum = relword >> 4;
			const char *name = aout16_sym_name(obj, symnum);
			if (name) {
				RzBinImport *imp = RZ_NEW0(RzBinImport);
				if (imp) {
					imp->name = rz_str_dup(name);
					imp->bind = "GLOBAL";
					imp->type = "FUNC";
					imp->ordinal = symnum;
					rel->import = imp;
				}
			}
		} else {
			/* Segment-relative: set target segment vaddr */
			switch (rtype) {
			case REL_TEXT:
				rel->addend = 0;
				rel->target_vaddr = text_vaddr;
				break;
			case REL_DATA:
				rel->addend = 0;
				rel->target_vaddr = data_vaddr;
				break;
			case REL_BSS:
				rel->addend = 0;
				rel->target_vaddr = data_vaddr + (ut64)obj->a_data * 2;
				break;
			case REL_BPTR:
				rel->addend = 0;
				break;
			default:
				break;
			}
		}

		rz_pvector_push(relocs, rel);
	}

	/* Process data relocations */
	for (i = 0; i < (int)obj->a_data; i++) {
		uint16_t relword = read_le16(buf, off_data_reloc + (ut64)i * 2);
		uint16_t rtype;
		RzBinReloc *rel;

		if (relword == 0) {
			continue;
		}

		rtype = relword & RELMSK;
		if (rtype == 0 || rtype == REL_ABS) {
			continue;
		}

		rel = RZ_NEW0(RzBinReloc);
		if (!rel) {
			continue;
		}

		rel->vaddr = data_vaddr + (ut64)i * 2;
		rel->paddr = obj->off_data + (ut64)i * 2;
		rel->additive = true;

		if (relword & REL_8) {
			rel->type = RZ_BIN_RELOC_8;
		} else {
			rel->type = RZ_BIN_RELOC_16;
		}

		if (rtype == REL_UNDEXT) {
			int symnum = relword >> 4;
			const char *name = aout16_sym_name(obj, symnum);
			if (name) {
				RzBinImport *imp = RZ_NEW0(RzBinImport);
				if (imp) {
					imp->name = rz_str_dup(name);
					imp->bind = "GLOBAL";
					imp->type = "FUNC";
					imp->ordinal = symnum;
					rel->import = imp;
				}
			}
		} else {
			switch (rtype) {
			case REL_TEXT:
				rel->addend = 0;
				rel->target_vaddr = text_vaddr;
				break;
			case REL_DATA:
				rel->addend = 0;
				rel->target_vaddr = data_vaddr;
				break;
			case REL_BSS:
				rel->addend = 0;
				rel->target_vaddr = data_vaddr + (ut64)obj->a_data * 2;
				break;
			case REL_BPTR:
				rel->addend = 0;
				break;
			default:
				break;
			}
		}

		rz_pvector_push(relocs, rel);
	}

	return relocs;
}

static RzBinInfo *aout16_info(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzBinInfo *info;
	int has_undef = 0;
	int i;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}

	/* Determine file type */
	if (obj->a_flag) {
		info->type = rz_str_dup("EXEC (reloc stripped)");
	} else {
		if (obj->syms) {
			for (i = 0; i < obj->nsyms; i++) {
				if ((obj->syms[i].type & N_TYPE_MASK) == N_UNDF &&
				    (obj->syms[i].type & N_EXT)) {
					has_undef = 1;
					break;
				}
			}
		}
		info->type = rz_str_dup(has_undef ? "REL (relocatable)" : "EXEC");
	}

	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->machine = rz_str_dup("Norsk Data ND-100");
	info->arch = rz_str_dup("nd100");
	info->bits = 16;
	info->big_endian = 0;
	info->has_va = 1;
	info->bclass = rz_str_dup("a.out16");

	return info;
}

static RzBinAddr *aout16_binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	struct aout16_obj *obj;
	RzBinAddr *ret;
	int i;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	if (sym == RZ_BIN_SPECIAL_SYMBOL_ENTRY) {
		ret = RZ_NEW0(RzBinAddr);
		if (ret) {
			ret->vaddr = (ut64)obj->a_entry * 2;
			ret->paddr = obj->off_text;
		}
		return ret;
	}

	if (sym == RZ_BIN_SPECIAL_SYMBOL_MAIN && obj->syms) {
		/* Search for _main or main symbol */
		for (i = 0; i < obj->nsyms; i++) {
			const char *name = aout16_sym_name(obj, i);
			if (!name) continue;
			if (!strcmp(name, "_main") || !strcmp(name, "main") ||
			    !strcmp(name, "_main_")) {
				ret = RZ_NEW0(RzBinAddr);
				if (ret) {
					ret->vaddr = (ut64)obj->syms[i].value * 2;
					ret->paddr = obj->off_text +
						(ut64)(obj->syms[i].value - obj->a_entry) * 2;
				}
				return ret;
			}
		}
	}
	return NULL;
}

static RzPVector *aout16_fields(RzBinFile *bf) {
	struct aout16_obj *obj;
	RzPVector *fields;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	fields = rz_pvector_new(free);
	if (!fields) {
		return NULL;
	}

	/* Header fields at fixed offsets */
	static const struct { const char *name; int offset; } hdr[] = {
		{"magic",     0}, {"text_size",  2}, {"data_size",  4},
		{"bss_size",  6}, {"syms_size",  8}, {"entry",     10},
		{"zp_size",  12}, {"flag",      14},
	};
	int i;
	for (i = 0; i < 8; i++) {
		RzBinField *f = RZ_NEW0(RzBinField);
		if (!f) continue;
		f->name = rz_str_dup(hdr[i].name);
		f->paddr = hdr[i].offset;
		f->vaddr = hdr[i].offset;
		f->size = 2;
		rz_pvector_push(fields, f);
	}

	return fields;
}

static void aout16_header(RzBinFile *bf) {
	struct aout16_obj *obj;

	if (!bf || !bf->o) {
		return;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return;
	}

	RzBin *bin = bf->rbin;
	PrintfCallback cb = bin->cb_printf;
	if (!cb) {
		return;
	}

	cb("a.out16 header:\n");
	cb("  magic:     0%o (0x%04x)\n", obj->a_magic, obj->a_magic);
	cb("  text:      %u words (%u bytes)\n", obj->a_text, obj->a_text * 2);
	cb("  data:      %u words (%u bytes)\n", obj->a_data, obj->a_data * 2);
	cb("  bss:       %u words (%u bytes)\n", obj->a_bss, obj->a_bss * 2);
	cb("  syms:      %u words (%d symbols)\n", obj->a_syms, obj->nsyms);
	cb("  entry:     0%o (word addr) = 0x%04x (byte addr)\n",
		obj->a_entry, obj->a_entry * 2);
	cb("  zero page: %u words\n", obj->a_zp);
	cb("  flag:      %u%s\n", obj->a_flag,
		obj->a_flag ? " (reloc stripped)" : "");
}

RzBinPlugin rz_bin_plugin_aout16 = {
	.name = "aout16",
	.desc = "Norsk Data ND-100 a.out16 format",
	.author = "Ronny Hansen",
	.version = "1.0.5",
	.license = "LGPL3",
	.check_buffer = &aout16_check_buffer,
	.load_buffer = &aout16_load_buffer,
	.destroy = &aout16_destroy,
	.baddr = &aout16_baddr,
	.entries = &aout16_entries,
	.maps = &aout16_maps,
	.sections = &aout16_sections,
	.symbols = &aout16_symbols,
	.imports = &aout16_imports,
	.relocs = &aout16_relocs,
	.info = &aout16_info,
	.binsym = &aout16_binsym,
	.fields = &aout16_fields,
	.header = &aout16_header,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_aout16,
	.version = RZ_VERSION,
};
#endif
