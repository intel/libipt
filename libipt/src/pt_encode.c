/*
 * Copyright (c) 2013-2014, Intel Corporation
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

#include "intel-pt.h"


int pt_init_encoder(struct pt_encoder *encoder,
		    const struct pt_config *config)
{
	if (!encoder || !config)
		return -pte_invalid;

	if (config->size != sizeof(*config))
		return -pte_invalid;

	if (!config->begin || !config->end || (config->end < config->begin))
		return -pte_invalid;

	encoder->begin = config->begin;
	encoder->end = config->end;
	encoder->pos = encoder->begin;

	return pte_ok;
}

int pt_encode_byte(struct pt_encoder *encoder, uint8_t byte)
{
	if (!encoder)
		return -pte_invalid;

	if (!encoder->pos)
		return -pte_nosync;

	if (encoder->pos < encoder->begin)
		return -pte_nosync;

	if (encoder->end <= encoder->pos)
		return -pte_nosync;

	*encoder->pos++ = byte;

	return 1;
}

static int pt_encode_ext_opc(struct pt_encoder *encoder, uint8_t opc)
{
	int bytes, total;

	total = 0;
	bytes = pt_encode_byte(encoder, pt_opc_ext);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_byte(encoder, opc);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_pad(struct pt_encoder *encoder)
{
	return pt_encode_byte(encoder, pt_opc_pad);
}

int pt_encode_psb(struct pt_encoder *encoder)
{
	uint8_t count;
	int bytes, total;

	total = 0;
	bytes = pt_encode_ext_opc(encoder, pt_ext_psb);
	if (bytes < 0)
		return bytes;

	total += bytes;
	for (count = 0; count < pt_psb_repeat_count; ++count) {
		bytes = pt_encode_byte(encoder, pt_psb_hi);
		if (bytes < 0)
			return bytes;

		total += bytes;
		bytes = pt_encode_byte(encoder, pt_psb_lo);
		if (bytes < 0)
			return bytes;

		total += bytes;
	}

	return total;
}

int pt_encode_psbend(struct pt_encoder *encoder)
{
	return pt_encode_ext_opc(encoder, pt_ext_psbend);
}

static int pt_encode_value(struct pt_encoder *encoder,
			    uint64_t val, int size)
{
	int bytes, total;

	total = 0;
	for (; size; --size, val >>= 8) {
		bytes = pt_encode_byte(encoder, (uint8_t) val);
		if (bytes < 0)
			return bytes;

		total += bytes;
	}

	return total;
}

static int pt_encode_ip_packet(struct pt_encoder *encoder, uint8_t opc,
			       uint64_t ip, enum pt_ip_compression ipc)
{
	int bytes, total, size;

	if (ipc & ~pt_opm_ipc_shr_mask)
		return -pte_invalid;

	opc |= ipc << pt_opm_ipc_shr;

	size = 0;
	total = 0;
	bytes = pt_encode_byte(encoder, opc);
	if (bytes < 0)
		return bytes;

	total += bytes;

	switch (ipc) {
	case pt_ipc_suppressed:
		size = 0;
		break;

	case pt_ipc_update_16:
		size = 2;
		break;

	case pt_ipc_update_32:
		size = 4;
		break;

	case pt_ipc_sext_48:
		size = 6;
		break;
	}

	bytes = pt_encode_value(encoder, ip, size);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_tip(struct pt_encoder *encoder, uint64_t ip,
		  enum pt_ip_compression ipc)
{
	return pt_encode_ip_packet(encoder, pt_opc_tip, ip, ipc);
}

int pt_encode_tnt_8(struct pt_encoder *encoder, uint8_t tnt, int size)
{
	uint8_t opc;
	int stop;

	if (size >= 7)
		return -pte_invalid;

	opc = tnt << pt_opm_tnt_8_shr;

	stop = size + pt_opm_tnt_8_shr;
	opc |= 1 << stop;

	return pt_encode_byte(encoder, opc);
}

int pt_encode_tnt_64(struct pt_encoder *encoder, uint64_t tnt, int size)
{
	uint64_t stop;
	int bytes, total;

	if (size >= pt_pl_tnt_64_bits)
		return -pte_invalid;

	/* The TNT stop bit. */
	stop = 1ull << size;

	/* Mask out any leftover high bits and set the stop bit. */
	tnt &= stop - 1;
	tnt |= stop;

	total = 0;
	bytes = pt_encode_ext_opc(encoder, pt_ext_tnt_64);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_value(encoder, tnt, pt_pl_tnt_64_size);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_tip_pge(struct pt_encoder *encoder, uint64_t ip,
		      enum pt_ip_compression ipc)
{
	return pt_encode_ip_packet(encoder, pt_opc_tip_pge, ip, ipc);
}

int pt_encode_tip_pgd(struct pt_encoder *encoder, uint64_t ip,
		      enum pt_ip_compression ipc)
{
	return pt_encode_ip_packet(encoder, pt_opc_tip_pgd, ip, ipc);
}

int pt_encode_fup(struct pt_encoder *encoder, uint64_t ip,
		  enum pt_ip_compression ipc)
{
	return pt_encode_ip_packet(encoder, pt_opc_fup, ip, ipc);
}

int pt_encode_pip(struct pt_encoder *encoder, uint64_t cr3)
{
	int bytes, total;

	cr3 >>= pt_pl_pip_shl;
	cr3 <<= pt_pl_pip_shr;

	total = 0;
	bytes = pt_encode_ext_opc(encoder, pt_ext_pip);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_value(encoder, cr3, pt_pl_pip_size);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_ovf(struct pt_encoder *encoder)
{
	return pt_encode_ext_opc(encoder, pt_ext_ovf);
}

static int pt_encode_mode(struct pt_encoder *encoder, uint8_t payload)
{
	int bytes, total;

	total = 0;
	bytes = pt_encode_byte(encoder, pt_opc_mode);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_byte(encoder, payload);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_mode_exec(struct pt_encoder *encoder, enum pt_exec_mode am)
{
	uint8_t mode;

	mode = pt_mol_exec;

	switch (am) {
	default:
		return -pte_invalid;

	case ptem_16bit:
		break;

	case ptem_32bit:
		mode |= pt_mob_exec_csd;
		break;

	case ptem_64bit:
		mode |= pt_mob_exec_csl;
		break;
	}

	return pt_encode_mode(encoder, mode);
}


int pt_encode_mode_tsx(struct pt_encoder *encoder, uint8_t bits)
{
	uint8_t mode;

	mode = pt_mol_tsx;
	mode |= (bits & pt_mom_bits);

	return pt_encode_mode(encoder, mode);
}

int pt_encode_tsc(struct pt_encoder *encoder, uint64_t tsc)
{
	int bytes, total;

	total = 0;
	bytes = pt_encode_byte(encoder, pt_opc_tsc);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_value(encoder, tsc, pt_pl_tsc_size);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}

int pt_encode_cbr(struct pt_encoder *encoder, uint8_t cbr)
{
	int bytes, total;

	total = 0;
	bytes = pt_encode_ext_opc(encoder, pt_ext_cbr);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_byte(encoder, cbr);
	if (bytes < 0)
		return bytes;

	total += bytes;
	bytes = pt_encode_byte(encoder, 0);
	if (bytes < 0)
		return bytes;

	total += bytes;
	return total;
}
