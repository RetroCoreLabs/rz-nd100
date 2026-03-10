/*
 * rz_bin_bpun.c - Rizin binary loader for ND-100 BPUN bootstrap files
 *
 * Copyright (c) 2025-2026 Ronny Hansen
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * BPUN (Bootstrap Punch) file format:
 *   - ASCII preamble with octal addresses (/ = location counter, ! = end)
 *   - Binary sections: address(2), count(2), data(count*2), checksum(2), action(2)
 *   - All binary values are big-endian 16-bit words
 *   - FloMon variant: 4 bytes per word (00 HI 00 LO)
 */

#include <rz_bin.h>
#include <rz_lib.h>

#define BPUN_MAX_WORDS 65536

struct bpun_obj {
	uint16_t start;         /* start address from preamble */
	uint16_t boot;          /* boot address */
	uint16_t load_addr;     /* load address of binary data */
	uint16_t word_count;    /* word count of binary data */
	int is_flomon;          /* FloMon format flag */
	ut8 *data;              /* raw file data for mapping */
	ut64 data_offset;       /* file offset where binary data starts */
	ut64 data_size;         /* size of binary data in bytes */
};

/*
 * Parse the BPUN preamble to extract start/boot addresses and
 * find where the binary data begins.
 */
static struct bpun_obj *bpun_parse(RzBuffer *buf) {
	struct bpun_obj *obj;
	ut8 b;
	char tmpstr[52];
	int tmppos = 0;
	uint16_t loc_counter = 0;
	uint16_t load_addr = 0;
	uint16_t last_value = 0;
	ut64 pos = 0;
	ut64 filesz;

	filesz = rz_buf_size(buf);
	if (filesz < 8) {
		return NULL;
	}

	obj = RZ_NEW0(struct bpun_obj);
	if (!obj) {
		return NULL;
	}

	/* Parse ASCII preamble */
	while (pos < filesz) {
		if (rz_buf_read_at(buf, pos, &b, 1) != 1) {
			break;
		}
		pos++;
		char c = (char)(b & 0x7F);

		if (c == '!') {
			/* End of preamble */
			if (tmppos > 0) {
				tmpstr[tmppos] = '\0';
				load_addr = (uint16_t)strtol(tmpstr, NULL, 8);
			}
			if (load_addr == obj->start) {
				obj->boot = last_value;
			} else {
				obj->boot = load_addr;
			}
			break;
		} else if (c == '/') {
			if (tmppos > 0) {
				tmpstr[tmppos] = '\0';
				loc_counter = (uint16_t)strtol(tmpstr, NULL, 8);
				last_value = loc_counter;
				obj->start = loc_counter;
				if (load_addr == 0) {
					load_addr = loc_counter;
				}
			}
			tmppos = 0;
		} else if (c >= '0' && c <= '9') {
			if (tmppos < 50) {
				tmpstr[tmppos++] = c;
			}
		} else if (c == 0x0D) {
			if (tmppos > 0) {
				tmpstr[tmppos] = '\0';
				last_value = (uint16_t)strtol(tmpstr, NULL, 8);
				tmppos = 0;
			}
		}
	}

	/* Now read the binary header: address(2) + count(2) */
	if (pos + 4 > filesz) {
		free(obj);
		return NULL;
	}

	ut8 hdr[4];
	if (rz_buf_read_at(buf, pos, hdr, 4) != 4) {
		free(obj);
		return NULL;
	}

	obj->load_addr = ((uint16_t)hdr[0] << 8) | hdr[1];
	obj->word_count = ((uint16_t)hdr[2] << 8) | hdr[3];

	/* Check for FloMon: address=0, count=0 followed by checksum=0 */
	if (obj->load_addr == 0 && obj->word_count == 0) {
		/* Possible FloMon - peek at checksum */
		if (pos + 6 <= filesz) {
			ut8 ck[2];
			rz_buf_read_at(buf, pos + 4, ck, 2);
			if (ck[0] == 0 && ck[1] == 0) {
				obj->is_flomon = 1;
				/* FloMon: after 6 zero bytes, count byte, then data */
				if (pos + 7 <= filesz) {
					ut8 cnt;
					rz_buf_read_at(buf, pos + 6, &cnt, 1);
					obj->word_count = cnt;
					obj->load_addr = obj->start;
					obj->data_offset = pos + 7;
					obj->data_size = obj->word_count * 4; /* 4 bytes per word in FloMon */
				}
			}
		}
	} else {
		obj->data_offset = pos + 4; /* skip address + count header */
		obj->data_size = (ut64)obj->word_count * 2;
	}

	return obj;
}

static bool bpun_check_buffer(RzBuffer *buf) {
	ut8 data[256];
	int n, i;
	int has_slash = 0;
	int has_digits = 0;

	n = rz_buf_read_at(buf, 0, data, sizeof(data));
	if (n < 4) {
		return false;
	}

	/*
	 * BPUN preamble is 7-bit ASCII with octal digits, '/' and '!'.
	 * Many BPUN files have NUL padding (up to ~200 bytes) before the
	 * actual preamble.  Paper tape files often have the MSB set as a
	 * parity/mark bit, so we mask with 0x7F.
	 */
	for (i = 0; i < n; i++) {
		char c = data[i] & 0x7F;

		if (c == 0) {
			continue;
		} else if (c == '!') {
			break;
		} else if (c == '/') {
			has_slash = 1;
		} else if (c >= '0' && c <= '7') {
			has_digits = 1;
		} else if (c == 0x0D || c == 0x0A || c == ' ') {
			continue;
		} else if (c < ' ') {
			return false;
		}
	}

	return (has_slash && has_digits);
}

static bool bpun_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	struct bpun_obj *bobj = bpun_parse(buf);
	if (!bobj) {
		return false;
	}
	obj->bin_obj = bobj;
	return true;
}

static void bpun_destroy(RzBinFile *bf) {
	struct bpun_obj *obj;

	if (!bf || !bf->o) {
		return;
	}
	obj = bf->o->bin_obj;
	if (obj) {
		free(obj->data);
		free(obj);
	}
	bf->o->bin_obj = NULL;
}

static ut64 bpun_baddr(RzBinFile *bf) {
	struct bpun_obj *obj;

	if (!bf || !bf->o) {
		return 0;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return 0;
	}
	/* Virtual address = load_addr * 2 (word address to byte address) */
	return (ut64)obj->load_addr * 2;
}

static RzPVector *bpun_entries(RzBinFile *bf) {
	struct bpun_obj *obj;
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

	/* Boot address as entry point (word addr -> byte addr) */
	entry->vaddr = (ut64)obj->boot * 2;
	entry->paddr = obj->data_offset + ((ut64)(obj->boot - obj->load_addr) * 2);
	entry->bits = 16;
	rz_pvector_push(entries, entry);

	return entries;
}

static RzPVector *bpun_maps(RzBinFile *bf) {
	struct bpun_obj *obj;
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

	map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(maps);
		return NULL;
	}

	map->paddr = obj->data_offset;
	map->psize = obj->data_size;
	map->vaddr = (ut64)obj->load_addr * 2;
	map->vsize = obj->data_size;
	map->perm = RZ_PERM_RX;
	map->name = rz_str_dup("code");
	rz_pvector_push(maps, map);

	return maps;
}

static RzPVector *bpun_sections(RzBinFile *bf) {
	struct bpun_obj *obj;
	RzPVector *sections;
	RzBinSection *sec;

	if (!bf || !bf->o) {
		return NULL;
	}
	obj = bf->o->bin_obj;
	if (!obj) {
		return NULL;
	}

	sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}

	sec = RZ_NEW0(RzBinSection);
	if (!sec) {
		rz_pvector_free(sections);
		return NULL;
	}

	sec->name = rz_str_dup("code");
	sec->paddr = obj->data_offset;
	sec->size = obj->data_size;
	sec->vaddr = (ut64)obj->load_addr * 2;
	sec->vsize = obj->data_size;
	sec->perm = RZ_PERM_RX;
	sec->bits = 16;
	rz_pvector_push(sections, sec);

	return sections;
}

static RzBinInfo *bpun_info(RzBinFile *bf) {
	struct bpun_obj *obj;
	RzBinInfo *info;

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

	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->type = rz_str_dup(obj->is_flomon ? "BPUN FloMon bootstrap" : "BPUN bootstrap");
	info->machine = rz_str_dup("Norsk Data ND-100");
	info->arch = rz_str_dup("nd100");
	info->bits = 16;
	info->big_endian = 1;
	info->has_va = 1;

	return info;
}

RzBinPlugin rz_bin_plugin_bpun = {
	.name = "bpun",
	.desc = "Norsk Data BPUN bootstrap format",
	.author = "Ronny Hansen",
	.version = "1.0.1",
	.license = "LGPL3",
	.check_buffer = &bpun_check_buffer,
	.load_buffer = &bpun_load_buffer,
	.destroy = &bpun_destroy,
	.baddr = &bpun_baddr,
	.entries = &bpun_entries,
	.maps = &bpun_maps,
	.sections = &bpun_sections,
	.info = &bpun_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_bpun,
	.version = RZ_VERSION,
};
#endif
