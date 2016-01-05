/*
 * Copyright (c) 2013-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "pt_ild.h"

#include <string.h>

/* SET UP 3 TABLES */

static uint8_t has_disp_regular[4][4][8];

static void init_has_disp_regular_table(void)
{
	uint8_t mod, rm;

	memset(has_disp_regular, 0, sizeof(has_disp_regular));

	/*fill eamode16 */
	has_disp_regular[ptem_16bit][0][6] = 2;
	for (rm = 0; rm < 8; rm++)
		for (mod = 1; mod <= 2; mod++)
			has_disp_regular[ptem_16bit][mod][rm] = mod;

	/*fill eamode32/64 */
	has_disp_regular[ptem_32bit][0][5] = 4;
	has_disp_regular[ptem_64bit][0][5] = 4;
	for (rm = 0; rm < 8; rm++) {
		has_disp_regular[ptem_32bit][1][rm] = 1;
		has_disp_regular[ptem_32bit][2][rm] = 4;

		has_disp_regular[ptem_64bit][1][rm] = 1;
		has_disp_regular[ptem_64bit][2][rm] = 4;
	}
}

static uint8_t eamode_table[2][4];

static void init_eamode_table(void)
{
	eamode_table[0][ptem_unknown] = ptem_unknown;
	eamode_table[0][ptem_16bit] = ptem_16bit;
	eamode_table[0][ptem_32bit] = ptem_32bit;
	eamode_table[0][ptem_64bit] = ptem_64bit;

	eamode_table[1][ptem_unknown] = ptem_unknown;
	eamode_table[1][ptem_16bit] = ptem_32bit;
	eamode_table[1][ptem_32bit] = ptem_16bit;
	eamode_table[1][ptem_64bit] = ptem_32bit;
}

static uint8_t has_sib_table[4][4][8];

static void init_has_sib_table(void)
{
	uint8_t mod;

	memset(has_sib_table, 0, sizeof(has_sib_table));

	/*for eamode32/64 there is sib byte for mod!=3 and rm==4 */
	for (mod = 0; mod <= 2; mod++) {
		has_sib_table[ptem_32bit][mod][4] = 1;
		has_sib_table[ptem_64bit][mod][4] = 1;
	}
}

/* SOME ACCESSORS */

static inline uint8_t get_byte(struct pt_ild *ild, uint8_t i)
{
	return ild->itext[i];
}

static inline uint8_t const *get_byte_ptr(struct pt_ild *ild, uint8_t i)
{
	return ild->itext + i;
}

static inline int mode_64b(struct pt_ild *ild)
{
	return ild->mode == ptem_64bit;
}

static inline int mode_32b(struct pt_ild *ild)
{
	return ild->mode == ptem_32bit;
}

static inline int bits_match(uint8_t x, uint8_t mask, uint8_t target)
{
	return (x & mask) == target;
}

static inline void set_error(struct pt_ild *ild)
{
	ild->u.s.error = 1;
}

/* accessors for REX.R/VEX R  */
static inline uint8_t pti_get_rex_vex_r(struct pt_ild *ild)
{
	if (ild->u.s.vexc5)
		return (ild->c5byte1 >> 7) & 1;
	else if (ild->u.s.vexc4)
		return (ild->c4byte1 >> 7) & 1;
	else if (ild->rex)
		return (ild->rex >> 2) & 1;
	return 0;
}

static inline uint8_t pti_get_rex_vex_w(struct pt_ild *ild)
{
	if (ild->u.s.vexc5)
		return 0;
	else if (ild->u.s.vexc4)
		return (ild->c4byte2 >> 7) & 1;
	else if (ild->rex)
		return (ild->rex >> 3) & 1;
	return 0;
}

static inline enum pt_exec_mode
pti_get_nominal_eosz_non64(struct pt_ild *ild)
{
	if (mode_32b(ild)) {
		if (ild->u.s.osz)
			return ptem_16bit;
		return ptem_32bit;
	}
	if (ild->u.s.osz)
		return ptem_32bit;
	return ptem_16bit;
}

static inline enum pt_exec_mode
pti_get_nominal_eosz(struct pt_ild *ild)
{
	if (mode_64b(ild)) {
		if (pti_get_rex_vex_w(ild))
			return ptem_64bit;
		if (ild->u.s.osz)
			return ptem_16bit;
		return ptem_32bit;
	}
	return pti_get_nominal_eosz_non64(ild);
}

static inline enum pt_exec_mode
pti_get_nominal_eosz_df64(struct pt_ild *ild)
{
	if (mode_64b(ild)) {
		if (pti_get_rex_vex_w(ild))
			return ptem_64bit;
		if (ild->u.s.osz)
			return ptem_16bit;
		/* only this next line of code is different relative
		   to pti_get_nominal_eosz(), above */
		return ptem_64bit;
	}
	return pti_get_nominal_eosz_non64(ild);
}

static inline enum pt_exec_mode
pti_get_nominal_easz_non64(struct pt_ild *ild)
{
	if (mode_32b(ild)) {
		if (ild->u.s.asz)
			return ptem_16bit;
		return ptem_32bit;
	}
	if (ild->u.s.asz)
		return ptem_32bit;
	return ptem_16bit;
}

static inline enum pt_exec_mode
pti_get_nominal_easz(struct pt_ild *ild)
{
	if (mode_64b(ild)) {
		if (ild->u.s.asz)
			return ptem_32bit;
		return ptem_64bit;
	}
	return pti_get_nominal_easz_non64(ild);
}

static inline uint8_t resolve_z(enum pt_exec_mode eosz, struct pt_ild *ild)
{
	static const uint8_t bytes[] = { 2, 4, 4 };
	unsigned int idx;

	idx = (unsigned int) eosz - 1;
	if (sizeof(bytes) <= idx) {
		set_error(ild);
		return 0;
	}

	return bytes[idx];
}

static inline uint8_t resolve_v(enum pt_exec_mode eosz, struct pt_ild *ild)
{
	static const uint8_t bytes[] = { 2, 4, 8 };
	unsigned int idx;

	idx = (unsigned int) eosz - 1;
	if (sizeof(bytes) <= idx) {
		set_error(ild);
		return 0;
	}

	return bytes[idx];
}

/*  DECODERS */

static void prefix_rex_dec(struct pt_ild *ild)
{
	uint8_t max_bytes = ild->max_bytes;
	uint8_t length = 0;
	uint8_t rex = 0;
	uint8_t nprefixes = 0;

	while (length < max_bytes) {
		uint8_t b = get_byte(ild, length);

		switch (b) {
		case 0x66:
			ild->u.s.osz = 1;
			/*ignore possible REX prefix encoutered earlier */
			rex = 0;
			break;

		case 0x67:
			ild->u.s.asz = 1;
			rex = 0;
			break;

			/* segment prefixes */
		case 0x2E:
		case 0x3E:
		case 0x26:
		case 0x36:
		case 0x64:
		case 0x65:
			/* ignore possible REX prefix encountered earlier */
			rex = 0;
			break;

		case 0xF0:
			ild->u.s.lock = 1;
			rex = 0;
			break;

		case 0xF3:
			ild->u.s.f3 = 1;
			ild->u.s.last_f2f3 = 3;
			rex = 0;
			break;

		case 0xF2:
			ild->u.s.f2 = 1;
			ild->u.s.last_f2f3 = 2;
			rex = 0;
			break;

		default:
			/*Take care of REX prefix */
			if (mode_64b(ild) && (b & 0xf0) == 0x40)
				rex = b;
			else
				goto out;
		}
		length++;
		nprefixes++;
	}
 out:
	ild->length = length;
	ild->rex = (uint8_t) rex;
	if (length >= max_bytes) {
		/* all available length was taken by prefixes, but we for sure
		 * need at least one additional byte for an opcode, hence we
		 * are out of bytes.
		 */
		set_error(ild);
		return;
	}
}

static void vex_opcode_dec(struct pt_ild *ild)
{
	uint8_t length = ild->length;

	ild->nominal_opcode = get_byte(ild, length);
	ild->nominal_opcode_pos = length;	/*FIXME: needed? */
	ild->length = length + 1;
}

static void vex_c5_dec(struct pt_ild *ild)
{
	uint8_t max_bytes = ild->max_bytes;
	uint8_t length = ild->length;

	if (mode_64b(ild)) {
		ild->u.s.vexc5 = 1;
		length++;	/* eat the c5 */
	} else if (length + 1 < max_bytes) {	/* non64b mode */
		uint8_t n = get_byte(ild, length + 1);

		if (bits_match(n, 0xC0, 0xC0)) {
			ild->u.s.vexc5 = 1;
			length++;	/* eat the c5 */
		} else {
			/* not c5 vex, keep going */
			return;
		}
	} else {
		set_error(ild);
		return;
	}

	/* vex payload processing */

	/* we want to make sure, that we have additional 2 bytes
	 * available for reading - for vex payload byte and opcode */
	if ((length + 2) <= max_bytes) {
		ild->c5byte1 = get_byte(ild, length);
		pti_set_map(ild, PTI_MAP_1);
		length++;	/* eat the vex payload byte */
		ild->length = length;
		vex_opcode_dec(ild);
	} else {
		set_error(ild);
	}
}

static void vex_c4_dec(struct pt_ild *ild)
{
	uint8_t max_bytes = ild->max_bytes;
	uint8_t length = ild->length;

	if (mode_64b(ild)) {
		ild->u.s.vexc4 = 1;
		length++;	/* eat the c4 */
	} else if (length + 1 < max_bytes) {	/* non64b mode */
		uint8_t n = get_byte(ild, length + 1);

		if (bits_match(n, 0xC0, 0xC0)) {
			ild->u.s.vexc4 = 1;
			length++;	/* eat the c4 */
		} else {
			/* not c4 vex, keep going */
			return;
		}
	} else {
		set_error(ild);
		return;
	}

	/* vex payload processing */

	/* we want to make sure, that we have additional 2 bytes
	 * available for reading - for vex payload byte and opcode */
	if ((length + 3) <= max_bytes) {
		ild->c4byte1 = get_byte(ild, length);
		ild->c4byte2 = get_byte(ild, length + 1);

		pti_set_map(ild, (pti_map_enum_t) (ild->c4byte1 & 0x1F));
		if (pti_get_map(ild) == PTI_MAP_3)
			ild->imm1_bytes = 1;

		length += 2;	/* eat the 2byte vex payload */
		ild->length = length;
		vex_opcode_dec(ild);
	} else {
		set_error(ild);
	}
}

static void vex_dec(struct pt_ild *ild)
{
	/* The prefix scanner checked the length for us so we know that there
	 * is at least 1B left.
	 */
	uint8_t b = get_byte(ild, ild->length);

	if (b == 0xC5)
		vex_c5_dec(ild);
	else if (b == 0xC4)
		vex_c4_dec(ild);
}

static void get_next_as_opcode(struct pt_ild *ild)
{
	uint8_t length = ild->length;

	if (length < ild->max_bytes) {
		ild->nominal_opcode = get_byte(ild, length);
		ild->nominal_opcode_pos = length;
		ild->length = length + 1;
	} else {
		set_error(ild);
	}
}

static void opcode_dec(struct pt_ild *ild)
{
	uint8_t length = ild->length;
	uint8_t b = get_byte(ild, length);

	/*no need to check max_bytes - it was checked in previous scanners */

	if (b != 0x0F) {	/* 1B opcodes, map 0 */
		pti_set_map(ild, PTI_MAP_0);
		ild->nominal_opcode = b;
		ild->nominal_opcode_pos = length;
		ild->length = length + 1;
		return;
	}

	length++;		/* eat the 0x0F */
	ild->nominal_opcode_pos = length;

	/* 0x0F opcodes MAPS 1,2,3 */
	if (length < ild->max_bytes) {
		uint8_t m = get_byte(ild, length);

		if (m == 0x38) {
			length++;	/* eat the 0x38 */
			pti_set_map(ild, PTI_MAP_2);
			ild->length = length;
			get_next_as_opcode(ild);
			return;
		} else if (m == 0x3A) {
			length++;	/* eat the 0x3A */
			pti_set_map(ild, PTI_MAP_3);
			ild->length = length;
			ild->imm1_bytes = 1;
			get_next_as_opcode(ild);
			return;
		} else if (m == 0x3B) {
			length++;	/* eat the 0x3B */
			pti_set_map(ild, PTI_MAP_INVALID);
			ild->length = length;
			get_next_as_opcode(ild);
			return;
		} else if (m > 0x38 && m <= 0x3F) {
			/* eat the 0x39...0x3F (minus 3A and 3B) */
			length++;
			pti_set_map(ild, PTI_MAP_INVALID);
			ild->length = length;
			get_next_as_opcode(ild);
			return;
		} else if (m == 0x0F) {	/* 3dNow */
			pti_set_map(ild, PTI_MAP_AMD3DNOW);
			ild->imm1_bytes = 1;
			/* real opcode is in immediate later on, but we need an
			 * opcode now. */
			ild->nominal_opcode = 0x0F;
			ild->length = length + 1;	/*eat the second 0F */
		} else {	/* map 1 (simple two byte opcodes) */
			length++;	/* eat the 2nd  opcode byte */
			ild->nominal_opcode = m;
			ild->nominal_opcode_pos = length;
			pti_set_map(ild, PTI_MAP_1);
			ild->length = length;
		}
	} else {
		set_error(ild);
	}
}

#include "pti-modrm-defs.h"
#include "pti-modrm.h"
#include "pti-disp-defs.h"
#include "pti-disp.h"

static void modrm_dec(struct pt_ild *ild)
{
	static uint8_t const *const has_modrm_2d[2] = {
		has_modrm_map_0x0,
		has_modrm_map_0x0F
	};
	int has_modrm = PTI_MODRM_FALSE;
	pti_map_enum_t map = pti_get_map(ild);

	if (map >= PTI_MAP_2)
		has_modrm = PTI_MODRM_TRUE;
	else
		has_modrm = has_modrm_2d[map][ild->nominal_opcode];
	if (has_modrm == PTI_MODRM_FALSE)
		return;
	if (has_modrm == PTI_MODRM_UNDEF)
		return;
	if (ild->length >= ild->max_bytes) {
		/* really >= here because we have not eaten the byte yet */
		set_error(ild);
		return;
	}
	ild->modrm_byte = get_byte(ild, ild->length);
	ild->length++;	/* eat modrm */
	if (has_modrm != PTI_MODRM_IGNORE_MOD) {
		/* set disp_bytes and sib using simple tables */

		uint8_t eamode = eamode_table[ild->u.s.asz][ild->mode];
		uint8_t mod = (uint8_t) pti_get_modrm_mod(ild);
		uint8_t rm = (uint8_t) pti_get_modrm_rm(ild);

		ild->disp_bytes = has_disp_regular[eamode][mod][rm];
		ild->u.s.sib = has_sib_table[eamode][mod][rm];
	}

}

static void sib_dec(struct pt_ild *ild)
{
	if (ild->u.s.sib) {
		uint8_t length = ild->length;

		if (length < ild->max_bytes) {
			ild->sib_byte = get_byte(ild, length);
			ild->length = length + 1;
			if (pti_get_sib_base(ild) == 5
			    && pti_get_modrm_mod(ild) == 0)
				ild->disp_bytes = 4;
		} else {
			set_error(ild);
		}
	}
}

static void compute_disp_dec(struct pt_ild *ild)
{
	/* set ild->disp_bytes for maps 0 and 1. */
	static uint8_t const *const map_map[] = {
		/* map 0 */ disp_bytes_map_0x0,
		/* map 1 */ disp_bytes_map_0x0F,
		/* map 2 */ 0,
		/* map 3 */ 0,
		/* amd3dnow */ 0,
		/* invalid */ 0
	};

	uint8_t const *const disp_table = map_map[ild->map];
	uint8_t disp_kind;

	if (disp_table == 0)
		return;
	disp_kind = disp_table[ild->nominal_opcode];
	switch (disp_kind) {
	case PTI_DISP_NONE:
		ild->disp_bytes = 0;
		break;

	case PTI_PRESERVE_DEFAULT:
		/* nothing to do */
		break;

	case PTI_BRDISP8:
		ild->disp_bytes = 1;
		break;

	case PTI_DISP_BUCKET_0_l1:
		/* BRDISPz(eosz) for 16/32 modes, and BRDISP32 for 64b mode */
		if (mode_64b(ild))
			ild->disp_bytes = 4;
		else {
			enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

			ild->disp_bytes = resolve_z(eosz, ild);
		}
		break;

	case PTI_MEMDISPv_DISP_WIDTH_ASZ_NONTERM_EASZ_l2: {
		/* MEMDISPv(easz) */
		enum pt_exec_mode easz = pti_get_nominal_easz(ild);

		ild->disp_bytes = resolve_v(easz, ild);
	}
		break;

	case PTI_BRDISPz_BRDISP_WIDTH_OSZ_NONTERM_EOSZ_l2: {
		/* BRDISPz(eosz) for 16/32/64 modes */
		enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

		ild->disp_bytes = resolve_z(eosz, ild);
	}
		break;

	case PTI_RESOLVE_BYREG_DISP_map0x0_op0xc7_l1:
		/* reg=0 -> preserve, reg=7 -> BRDISPz(eosz) */
		if (ild->map == PTI_MAP_0 && pti_get_modrm_reg(ild) == 7) {
			enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

			ild->disp_bytes = resolve_z(eosz, ild);
		}
		break;

	default:
		set_error(ild);
		break;
	}
}

static void disp_dec(struct pt_ild *ild)
{
	uint8_t disp_bytes;

	if (ild->disp_bytes == 0 && pti_get_map(ild) < PTI_MAP_2)
		compute_disp_dec(ild);

	disp_bytes = ild->disp_bytes;
	if (disp_bytes == 0)
		return;
	if (ild->length + disp_bytes > ild->max_bytes) {
		set_error(ild);
		return;
	}

	/*Record only position; must be able to re-read itext bytes for actual
	   value. (SMC/CMC issue). */
	ild->disp_pos = ild->length;
	ild->length += disp_bytes;
}

#include "pti-imm-defs.h"
#include "pti-imm.h"

static void set_imm_bytes(struct pt_ild *ild)
{
	/*: set ild->imm1_bytes and  ild->imm2_bytes for maps 0/1 */
	static uint8_t const *const map_map[] = {
		/* map 0 */ imm_bytes_map_0x0,
		/* map 1 */ imm_bytes_map_0x0F,
		/* map 2 */ 0,
		/* map 3 */ 0,
		/* amd3dnow */ 0,
		/* invalid */ 0
	};
	uint8_t const *const map_imm = map_map[ild->map];
	uint8_t imm_code;

	if (map_imm == 0)
		return;
	imm_code = map_imm[ild->nominal_opcode];
	switch (imm_code) {
	case PTI_IMM_NONE:
	case PTI_0_IMM_WIDTH_CONST_l2:
		/* nothing for either case */
		break;

	case PTI_UIMM8_IMM_WIDTH_CONST_l2:
		ild->imm1_bytes = 1;
		break;

	case PTI_SIMM8_IMM_WIDTH_CONST_l2:
		ild->imm1_bytes = 1;
		break;

	case PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2: {
		/* SIMMz(eosz) */
		enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

		ild->imm1_bytes = resolve_z(eosz, ild);
	}
		break;

	case PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2: {
		/* UIMMv(eosz) */
		enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

		ild->imm1_bytes = resolve_v(eosz, ild);
	}
		break;

	case PTI_UIMM16_IMM_WIDTH_CONST_l2:
		ild->imm1_bytes = 2;
		break;

	case PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_DF64_EOSZ_l2: {
		/* push defaults to eosz64 in 64b mode, then uses SIMMz */
		enum pt_exec_mode eosz = pti_get_nominal_eosz_df64(ild);

		ild->imm1_bytes = resolve_z(eosz, ild);
	}
		break;

	case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf7_l1:
		if (ild->map == PTI_MAP_0 && pti_get_modrm_reg(ild) < 2) {
			enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

			ild->imm1_bytes = resolve_z(eosz, ild);
		}
		break;

	case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xc7_l1:
		if (ild->map == PTI_MAP_0 && pti_get_modrm_reg(ild) == 0) {
			enum pt_exec_mode eosz = pti_get_nominal_eosz(ild);

			ild->imm1_bytes = resolve_z(eosz, ild);
		}
		break;

	case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf6_l1:
		if (ild->map == PTI_MAP_0 && pti_get_modrm_reg(ild) < 2)
			ild->imm1_bytes = 1;

		break;

	case PTI_IMM_hasimm_map0x0_op0xc8_l1:
		if (ild->map == PTI_MAP_0) {
			/*enter -> imm1=2, imm2=1 */
			ild->imm1_bytes = 2;
			ild->imm2_bytes = 1;
		}
		break;

	case PTI_IMM_hasimm_map0x0F_op0x78_l1:
		/* AMD SSE4a (insertq/extrq use  osz/f2) vs vmread
		 * (no prefixes)
		 */
		if (ild->map == PTI_MAP_1) {
			if (ild->u.s.osz || ild->u.s.last_f2f3 == 2) {
				ild->imm1_bytes = 1;
				ild->imm2_bytes = 1;
			}
		}
		break;

	default:
		break;
	}
}

static void imm_dec(struct pt_ild *ild)
{
	if (ild->map == PTI_MAP_AMD3DNOW) {
		if (ild->length < ild->max_bytes) {
			ild->nominal_opcode = get_byte(ild, ild->length);
			ild->length++;
		} else
			set_error(ild);
		return;
	}
	set_imm_bytes(ild);
	if (ild->imm1_bytes == 0)
		return;

	if (ild->length + ild->imm1_bytes > ild->max_bytes) {
		set_error(ild);
		return;
	}
	/*FIXME: could record immediate position if ever needed... */
	ild->length += ild->imm1_bytes;

	if (ild->imm2_bytes == 0)
		return;

	if (ild->length + ild->imm2_bytes > ild->max_bytes) {
		set_error(ild);
		return;
	}
	ild->length += ild->imm2_bytes;
}

static void decode(struct pt_ild *ild)
{
	prefix_rex_dec(ild);
	vex_dec(ild);
	if (ild->nominal_opcode_pos == 0)
		opcode_dec(ild);
	modrm_dec(ild);
	sib_dec(ild);
	disp_dec(ild);
	imm_dec(ild);
}

static inline int64_t sign_extend_bq(int8_t x)
{
	return x;
}

static inline int64_t sign_extend_wq(int16_t x)
{
	return x;
}

static inline int64_t sign_extend_dq(int32_t x)
{
	return x;
}

static void set_branch_target(struct pt_ild *ild)
{
	int64_t npc;
	uint64_t sign_extended_disp = 0;

	if (ild->disp_bytes == 1)
		sign_extended_disp =
		    sign_extend_bq(get_byte(ild, ild->disp_pos));
	else if (ild->disp_bytes == 2) {
		int16_t *w = (int16_t *) (get_byte_ptr(ild, ild->disp_pos));

		sign_extended_disp = sign_extend_wq(*w);
	} else if (ild->disp_bytes == 4) {
		int32_t *d = (int32_t *) (get_byte_ptr(ild, ild->disp_pos));

		sign_extended_disp = sign_extend_dq(*d);
	} else {
		set_error(ild);
		return;
	}

	npc = (int64_t) (ild->runtime_address + ild->length);
	ild->direct_target = (uint64_t) (npc + sign_extended_disp);
}

/*  MAIN ENTRY POINTS */

void pt_ild_init(void)
{	/* initialization */
	init_has_disp_regular_table();
	init_has_sib_table();
	init_eamode_table();
}

int pt_instruction_length_decode(struct pt_ild *ild)
{
	ild->u.i = 0;
	ild->imm1_bytes = 0;
	ild->imm2_bytes = 0;
	ild->disp_bytes = 0;
	ild->nominal_opcode_pos = 0;
	ild->modrm_byte = 0;
	ild->map = PTI_MAP_INVALID;

	if (!ild->mode) {
		set_error(ild);
		return 1;
	}

	decode(ild);
	return ild->u.s.error == 0;
}

int pt_instruction_decode(struct pt_ild *ild)
{
	uint8_t opcode = ild->nominal_opcode;
	uint8_t map = pti_get_map(ild);

	ild->iclass = PTI_INST_INVALID;

	if (ild->map > PTI_MAP_1)
		return 0;	/* uninteresting */
	if (ild->u.s.vexc4 || ild->u.s.vexc5)
		return 0;	/* uninteresting */

	/* PTI_INST_JCC,   70...7F, 0F (0x80...0x8F) */
	if (opcode >= 0x70 && opcode <= 0x7F) {
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_JCC;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;
	}
	if (opcode >= 0x80 && opcode <= 0x8F) {
		if (map == PTI_MAP_1) {
			ild->iclass = PTI_INST_JCC;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;
	}

	switch (ild->nominal_opcode) {
	case 0x9A:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_CALL_9A;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.call = 1;
			return 1;
		}
		return 0;

	case 0xFF:
		if (map == PTI_MAP_0) {
			uint8_t reg = pti_get_modrm_reg(ild);

			if (reg == 2) {
				ild->iclass = PTI_INST_CALL_FFr2;
				ild->u.s.branch = 1;
				ild->u.s.call = 1;
				return 1;
			} else if (reg == 3) {
				ild->iclass = PTI_INST_CALL_FFr3;
				ild->u.s.branch = 1;
				ild->u.s.branch_far = 1;
				ild->u.s.call = 1;
				return 1;
			} else if (reg == 4) {
				ild->iclass = PTI_INST_JMP_FFr4;
				ild->u.s.branch = 1;
				return 1;
			} else if (reg == 5) {
				ild->iclass = PTI_INST_JMP_FFr5;
				ild->u.s.branch = 1;
				ild->u.s.branch_far = 1;
				return 1;
			}
		}
		return 0;

	case 0xE8:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_CALL_E8;
			ild->u.s.branch = 1;
			ild->u.s.call = 1;
			ild->u.s.branch_direct = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xCD:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_INT;
			return 1;
		}
		return 0;

	case 0xCC:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_INT3;
			return 1;
		}
		return 0;

	case 0xCE:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_INTO;
			return 1;
		}
		return 0;

	case 0xF1:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_INT1;
			return 1;
		}
		return 0;

	case 0xCF:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_IRET;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0xE9:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_JMP_E9;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xEA:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_JMP_EA;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			/* FIXME: We do not set the branch target. */
			return 1;
		}
		return 0;

	case 0xEB:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_JMP_EB;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xE3:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_JrCXZ;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xE0:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_LOOPNE;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xE1:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_LOOPE;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0xE2:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_LOOP;
			ild->u.s.branch = 1;
			ild->u.s.branch_direct = 1;
			ild->u.s.cond = 1;
			set_branch_target(ild);
			return 1;
		}
		return 0;

	case 0x22:
		if (map == PTI_MAP_1)
			if (pti_get_modrm_reg(ild) == 3)
				if (pti_get_rex_vex_r(ild) == 0) {
					ild->iclass = PTI_INST_MOV_CR3;
					return 1;
				}
		return 0;

	case 0xC3:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_RET_C3;
			ild->u.s.branch = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0xC2:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_RET_C2;
			ild->u.s.branch = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0xCB:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_RET_CB;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0xCA:
		if (map == PTI_MAP_0) {
			ild->iclass = PTI_INST_RET_CA;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0x05:
		if (map == PTI_MAP_1) {
			ild->iclass = PTI_INST_SYSCALL;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.call = 1;
			return 1;
		}
		return 0;

	case 0x34:
		if (map == PTI_MAP_1) {
			ild->iclass = PTI_INST_SYSENTER;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.call = 1;
			return 1;
		}
		return 0;

	case 0x35:
		if (map == PTI_MAP_1) {
			ild->iclass = PTI_INST_SYSEXIT;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0x07:
		if (map == PTI_MAP_1) {
			ild->iclass = PTI_INST_SYSRET;
			ild->u.s.branch = 1;
			ild->u.s.branch_far = 1;
			ild->u.s.ret = 1;
			return 1;
		}
		return 0;

	case 0x01:
		if (map == PTI_MAP_1) {
			switch (ild->modrm_byte) {
			case 0xc1:
				ild->iclass = PTI_INST_VMCALL;
				ild->u.s.branch = 1;
				ild->u.s.branch_far = 1;
				ild->u.s.ret = 1;
				return 1;

			case 0xc2:
				ild->iclass = PTI_INST_VMLAUNCH;
				ild->u.s.branch = 1;
				ild->u.s.branch_far = 1;
				ild->u.s.call = 1;
				return 1;

			case 0xc3:
				ild->iclass = PTI_INST_VMRESUME;
				ild->u.s.branch = 1;
				ild->u.s.branch_far = 1;
				ild->u.s.call = 1;
				return 1;

			default:
				return 0;
			}
		}
		return 0;

	case 0xc7:
		if (map == PTI_MAP_1 &&
		    pti_get_modrm_mod(ild) != 3 &&
		    pti_get_modrm_reg(ild) == 6) {
			ild->iclass = PTI_INST_VMPTRLD;
			return 1;
		}
		return 0;

	default:
		break;
	}

	return 0;

}
