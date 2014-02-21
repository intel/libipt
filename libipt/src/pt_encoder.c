/*
 * Copyright (c) 2014, Intel Corporation
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

#include "pt_encoder.h"

#include <string.h>


int pt_encoder_init(struct pt_encoder *encoder, const struct pt_config *config)
{
	uint8_t *begin, *end;

	if (!encoder || !config)
		return -pte_invalid;

	if (config->size != sizeof(*config))
		return -pte_bad_config;

	begin = config->begin;
	end = config->end;

	if (!begin || !end || end < begin)
		return -pte_bad_config;

	memset(encoder, 0, sizeof(*encoder));

	encoder->config = *config;
	encoder->pos = begin;

	return 0;
}

void pt_encoder_fini(struct pt_encoder *encoder)
{
	/* Nothing to do. */
}

struct pt_encoder *pt_alloc_encoder(const struct pt_config *config)
{
	struct pt_encoder *encoder;
	int errcode;

	encoder = malloc(sizeof(*encoder));
	if (!encoder)
		return NULL;

	errcode = pt_encoder_init(encoder, config);
	if (errcode < 0) {
		free(encoder);
		return NULL;
	}

	return encoder;
}

void pt_free_encoder(struct pt_encoder *encoder)
{
	pt_encoder_fini(encoder);
	free(encoder);
}

int pt_enc_sync_set(struct pt_encoder *encoder, uint64_t offset)
{
	uint8_t *begin, *end, *pos;

	if (!encoder)
		return -pte_invalid;

	begin = encoder->config.begin;
	end = encoder->config.end;
	pos = begin + offset;

	if (end < pos || pos < begin)
		return -pte_eos;

	encoder->pos = pos;
	return 0;
}

int pt_enc_get_offset(struct pt_encoder *encoder, uint64_t *offset)
{
	const uint8_t *raw, *begin;

	if (!encoder || !offset)
		return -pte_invalid;

	raw = encoder->pos;
	if (!raw)
		return -pte_nosync;

	begin = encoder->config.begin;
	if (!begin)
		return -pte_internal;

	*offset = raw - begin;
	return 0;
}

/* Check the remaining space.
 *
 * Returns zero if there are at least \@size bytes of free space available in
 * \@encoder's PT buffer.
 *
 * Returns -pte_eos if not enough space is available.
 * Returns -pte_internal if \@encoder is NULL.
 * Returns -pte_nosync if \@encoder is not synchronized.
 */
static int pt_reserve(const struct pt_encoder *encoder, unsigned int size)
{
	const uint8_t *begin, *end, *pos;

	if (!encoder)
		return -pte_internal;

	pos = encoder->pos;
	if (!pos)
		return -pte_nosync;

	begin = encoder->config.begin;
	end = encoder->config.end;

	pos += size;
	if (pos < begin || end < pos)
		return -pte_eos;

	return 0;
}

/* Return the size of an IP payload based on its IP compression.
 *
 * Returns -pte_bad_packet if \@ipc is not a valid IP compression.
 */
static int pt_ipc_size(enum pt_ip_compression ipc)
{
	switch (ipc) {
	default:
		return -pte_invalid;

	case pt_ipc_suppressed:
		return 0;

	case pt_ipc_update_16:
		return pt_pl_ip_upd16_size;

	case pt_ipc_update_32:
		return pt_pl_ip_upd32_size;

	case pt_ipc_sext_48:
		return pt_pl_ip_sext48_size;
	}
}

/* Encode an integer value.
 *
 * Writes the \@size least signifficant bytes of \@value starting from \@pos.
 *
 * The caller needs to ensure that there is enough space available.
 *
 * Returns the updated position.
 */
static uint8_t *pt_encode_int(uint8_t *pos, uint64_t val, int size)
{
	for (; size; --size, val >>= 8)
		*pos++ = (uint8_t) val;

	return pos;
}

/* Encode an IP packet.
 *
 * Write an IP packet with opcode \@opc and payload from \@packet if there is
 * enough space in \@encoder's PT buffer.
 *
 * Returns the number of bytes written on success.
 *
 * Returns -pte_eos if there is not enough space.
 * Returns -pte_internal if \@encoder or \@packet is NULL.
 * Returns -pte_invalid if \@packet.ipc is not valid.
 */
static int pt_encode_ip(struct pt_encoder *encoder, enum pt_opcode op,
			const struct pt_packet_ip *packet)
{
	uint8_t *pos;
	uint8_t opc, ipc;
	int size, errcode;

	if (!encoder || !packet)
		return pte_internal;

	size = pt_ipc_size(packet->ipc);
	if (size < 0)
		return size;

	errcode = pt_reserve(encoder, /* opc size = */ 1 + size);
	if (errcode < 0)
		return errcode;

	/* We already checked the ipc in pt_ipc_size(). */
	ipc = (uint8_t) (packet->ipc << pt_opm_ipc_shr);
	opc = (uint8_t) op;

	pos = encoder->pos;
	*pos++ = opc | ipc;

	encoder->pos = pt_encode_int(pos, packet->ip, size);
	return /* opc size = */ 1 + size;
}

int pt_enc_next(struct pt_encoder *encoder, const struct pt_packet *packet)
{
	uint8_t *pos, *begin;
	int errcode;

	if (!encoder || !packet)
		return -pte_invalid;

	pos = begin = encoder->pos;
	switch (packet->type) {
	case ppt_pad:
		errcode = pt_reserve(encoder, ptps_pad);
		if (errcode < 0)
			return errcode;

		*pos++ = pt_opc_pad;

		encoder->pos = pos;
		return (int) (pos - begin);

	case ppt_psb: {
		uint64_t psb;

		errcode = pt_reserve(encoder, ptps_psb);
		if (errcode < 0)
			return errcode;

		psb = ((uint64_t) pt_psb_hilo << 48 |
		       (uint64_t) pt_psb_hilo << 32 |
		       (uint64_t) pt_psb_hilo << 16 |
		       (uint64_t) pt_psb_hilo);

		pos = pt_encode_int(pos, psb, 8);
		pos = pt_encode_int(pos, psb, 8);

		encoder->pos = pos;
		return (int) (pos - begin);
	}

	case ppt_psbend:
		errcode = pt_reserve(encoder, ptps_psbend);
		if (errcode < 0)
			return errcode;

		*pos++ = pt_opc_ext;
		*pos++ = pt_ext_psbend;

		encoder->pos = pos;
		return (int) (pos - begin);

	case ppt_ovf:
		errcode = pt_reserve(encoder, ptps_ovf);
		if (errcode < 0)
			return errcode;

		*pos++ = pt_opc_ext;
		*pos++ = pt_ext_ovf;

		encoder->pos = pos;
		return (int) (pos - begin);

	case ppt_fup:
		return pt_encode_ip(encoder, pt_opc_fup, &packet->payload.ip);

	case ppt_tip:
		return pt_encode_ip(encoder, pt_opc_tip, &packet->payload.ip);

	case ppt_tip_pge:
		return pt_encode_ip(encoder, pt_opc_tip_pge,
				    &packet->payload.ip);

	case ppt_tip_pgd:
		return pt_encode_ip(encoder, pt_opc_tip_pgd,
				    &packet->payload.ip);

	case ppt_tnt_8: {
		uint8_t opc, stop;

		if (packet->payload.tnt.bit_size >= 7)
			return -pte_bad_packet;

		errcode = pt_reserve(encoder, ptps_tnt_8);
		if (errcode < 0)
			return errcode;

		stop = packet->payload.tnt.bit_size + pt_opm_tnt_8_shr;
		opc = (uint8_t) packet->payload.tnt.payload << pt_opm_tnt_8_shr;

		*pos++ = opc | (1 << stop);

		encoder->pos = pos;
		return (int) (pos - begin);
	}

	case ppt_tnt_64: {
		uint64_t tnt, stop;

		errcode = pt_reserve(encoder, ptps_tnt_64);
		if (errcode < 0)
			return errcode;

		if (packet->payload.tnt.bit_size >= pt_pl_tnt_64_bits)
			return -pte_invalid;

		stop = 1ull << packet->payload.tnt.bit_size;
		tnt = packet->payload.tnt.payload;

		if (tnt & ~(stop - 1))
			return -pte_invalid;

		*pos++ = pt_opc_ext;
		*pos++ = pt_ext_tnt_64;
		pos = pt_encode_int(pos, tnt | stop, pt_pl_tnt_64_size);

		encoder->pos = pos;
		return (int) (pos - begin);
	}

	case ppt_mode: {
		uint8_t mode;

		errcode = pt_reserve(encoder, ptps_mode);
		if (errcode < 0)
			return errcode;

		switch (packet->payload.mode.leaf) {
		default:
			return -pte_bad_packet;

		case pt_mol_exec:
			mode = pt_mol_exec;

			if (packet->payload.mode.bits.exec.csl)
				mode |= pt_mob_exec_csl;

			if (packet->payload.mode.bits.exec.csd)
				mode |= pt_mob_exec_csd;
			break;

		case pt_mol_tsx:
			mode = pt_mol_tsx;

			if (packet->payload.mode.bits.tsx.intx)
				mode |= pt_mob_tsx_intx;

			if (packet->payload.mode.bits.tsx.abrt)
				mode |= pt_mob_tsx_abrt;
			break;
		}

		*pos++ = pt_opc_mode;
		*pos++ = mode;

		encoder->pos = pos;
		return (int) (pos - begin);
	}

	case ppt_pip: {
		uint64_t cr3;

		errcode = pt_reserve(encoder, ptps_pip);
		if (errcode < 0)
			return errcode;

		cr3 = packet->payload.pip.cr3;
		cr3 >>= pt_pl_pip_shl;
		cr3 <<= pt_pl_pip_shr;

		*pos++ = pt_opc_ext;
		*pos++ = pt_ext_pip;
		pos = pt_encode_int(pos, cr3, pt_pl_pip_size);

		encoder->pos = pos;
		return (int) (pos - begin);
	}

	case ppt_tsc:
		errcode = pt_reserve(encoder, ptps_tsc);
		if (errcode < 0)
			return errcode;

		*pos++ = pt_opc_tsc;
		pos = pt_encode_int(pos, packet->payload.tsc.tsc,
				    pt_pl_tsc_size);

		encoder->pos = pos;
		return (int) (pos - begin);

	case ppt_cbr:
		errcode = pt_reserve(encoder, ptps_cbr);
		if (errcode < 0)
			return errcode;

		*pos++ = pt_opc_ext;
		*pos++ = pt_ext_cbr;
		*pos++ = packet->payload.cbr.ratio;
		*pos++ = 0;

		encoder->pos = pos;
		return (int) (pos - begin);

	case ppt_unknown:
	case ppt_invalid:
		return -pte_bad_opc;
	}

	return -pte_bad_opc;
}

int pt_encode_pad(struct pt_encoder *encoder)
{
	struct pt_packet packet;

	packet.type = ppt_pad;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_psb(struct pt_encoder *encoder)
{
	struct pt_packet packet;

	packet.type = ppt_psb;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_psbend(struct pt_encoder *encoder)
{
	struct pt_packet packet;

	packet.type = ppt_psbend;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tip(struct pt_encoder *encoder, uint64_t ip,
		  enum pt_ip_compression ipc)
{
	struct pt_packet packet;

	packet.type = ppt_tip;
	packet.payload.ip.ip = ip;
	packet.payload.ip.ipc = ipc;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tnt_8(struct pt_encoder *encoder, uint8_t tnt, int size)
{
	struct pt_packet packet;

	packet.type = ppt_tnt_8;
	packet.payload.tnt.bit_size = (uint8_t) size;
	packet.payload.tnt.payload = tnt;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tnt_64(struct pt_encoder *encoder, uint64_t tnt, int size)
{
	struct pt_packet packet;

	packet.type = ppt_tnt_64;
	packet.payload.tnt.bit_size = (uint8_t) size;
	packet.payload.tnt.payload = tnt;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tip_pge(struct pt_encoder *encoder, uint64_t ip,
		      enum pt_ip_compression ipc)
{
	struct pt_packet packet;

	packet.type = ppt_tip_pge;
	packet.payload.ip.ip = ip;
	packet.payload.ip.ipc = ipc;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tip_pgd(struct pt_encoder *encoder, uint64_t ip,
		      enum pt_ip_compression ipc)
{
	struct pt_packet packet;

	packet.type = ppt_tip_pgd;
	packet.payload.ip.ip = ip;
	packet.payload.ip.ipc = ipc;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_fup(struct pt_encoder *encoder, uint64_t ip,
		  enum pt_ip_compression ipc)
{
	struct pt_packet packet;

	packet.type = ppt_fup;
	packet.payload.ip.ip = ip;
	packet.payload.ip.ipc = ipc;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_pip(struct pt_encoder *encoder, uint64_t cr3)
{
	struct pt_packet packet;

	packet.type = ppt_pip;
	packet.payload.pip.cr3 = cr3;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_ovf(struct pt_encoder *encoder)
{
	struct pt_packet packet;

	packet.type = ppt_ovf;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_mode_exec(struct pt_encoder *encoder, enum pt_exec_mode mode)
{
	struct pt_packet packet;

	packet.type = ppt_mode;
	packet.payload.mode.leaf = pt_mol_exec;
	packet.payload.mode.bits.exec = pt_set_exec_mode(mode);

	return pt_enc_next(encoder, &packet);
}


int pt_encode_mode_tsx(struct pt_encoder *encoder, uint8_t bits)
{
	struct pt_packet packet;

	packet.type = ppt_mode;
	packet.payload.mode.leaf = pt_mol_tsx;

	if (bits & pt_mob_tsx_intx)
		packet.payload.mode.bits.tsx.intx = 1;
	else
		packet.payload.mode.bits.tsx.intx = 0;

	if (bits & pt_mob_tsx_abrt)
		packet.payload.mode.bits.tsx.abrt = 1;
	else
		packet.payload.mode.bits.tsx.abrt = 0;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_tsc(struct pt_encoder *encoder, uint64_t tsc)
{
	struct pt_packet packet;

	packet.type = ppt_tsc;
	packet.payload.tsc.tsc = tsc;

	return pt_enc_next(encoder, &packet);
}

int pt_encode_cbr(struct pt_encoder *encoder, uint8_t cbr)
{
	struct pt_packet packet;

	packet.type = ppt_cbr;
	packet.payload.cbr.ratio = cbr;

	return pt_enc_next(encoder, &packet);
}
