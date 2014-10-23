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

#include "pt_decoder_function.h"
#include "pt_packet_decode.h"
#include "pt_decoder.h"

#include "intel-pt.h"


const struct pt_decoder_function pt_decode_unknown = {
	/* .packet = */ pt_pkt_decode_unknown,
	/* .decode = */ pt_qry_decode_unknown,
	/* .header = */ pt_qry_decode_unknown,
	/* .flags =  */ pdff_unknown
};

const struct pt_decoder_function pt_decode_pad = {
	/* .packet = */ pt_pkt_decode_pad,
	/* .decode = */ pt_qry_decode_pad,
	/* .header = */ pt_qry_decode_pad,
	/* .flags =  */ 0
};

const struct pt_decoder_function pt_decode_psb = {
	/* .packet = */ pt_pkt_decode_psb,
	/* .decode = */ pt_qry_decode_psb,
	/* .header = */ pt_qry_header_psb,
	/* .flags =  */ 0
};

const struct pt_decoder_function pt_decode_tip = {
	/* .packet = */ pt_pkt_decode_tip,
	/* .decode = */ pt_qry_decode_tip,
	/* .header = */ NULL,
	/* .flags =  */ pdff_tip
};

const struct pt_decoder_function pt_decode_tnt_8 = {
	/* .packet = */ pt_pkt_decode_tnt_8,
	/* .decode = */ pt_qry_decode_tnt_8,
	/* .header = */ NULL,
	/* .flags =  */ pdff_tnt
};

const struct pt_decoder_function pt_decode_tnt_64 = {
	/* .packet = */ pt_pkt_decode_tnt_64,
	/* .decode = */ pt_qry_decode_tnt_64,
	/* .header = */ NULL,
	/* .flags =  */ pdff_tnt
};

const struct pt_decoder_function pt_decode_tip_pge = {
	/* .packet = */ pt_pkt_decode_tip_pge,
	/* .decode = */ pt_qry_decode_tip_pge,
	/* .header = */ NULL,
	/* .flags =  */ pdff_event
};

const struct pt_decoder_function pt_decode_tip_pgd = {
	/* .packet = */ pt_pkt_decode_tip_pgd,
	/* .decode = */ pt_qry_decode_tip_pgd,
	/* .header = */ NULL,
	/* .flags =  */ pdff_event
};

const struct pt_decoder_function pt_decode_fup = {
	/* .packet = */ pt_pkt_decode_fup,
	/* .decode = */ pt_qry_decode_fup,
	/* .header = */ pt_qry_header_fup,
	/* .flags =  */ pdff_fup
};

const struct pt_decoder_function pt_decode_pip = {
	/* .packet = */ pt_pkt_decode_pip,
	/* .decode = */ pt_qry_decode_pip,
	/* .header = */ pt_qry_header_pip,
	/* .flags =  */ pdff_event
};

const struct pt_decoder_function pt_decode_ovf = {
	/* .packet = */ pt_pkt_decode_ovf,
	/* .decode = */ pt_qry_decode_ovf,
	/* .header = */ NULL,
	/* .flags =  */ pdff_psbend
};

const struct pt_decoder_function pt_decode_mode = {
	/* .packet = */ pt_pkt_decode_mode,
	/* .decode = */ pt_qry_decode_mode,
	/* .header = */ pt_qry_header_mode,
	/* .flags =  */ pdff_event
};

const struct pt_decoder_function pt_decode_psbend = {
	/* .packet = */ pt_pkt_decode_psbend,
	/* .decode = */ pt_qry_decode_psbend,
	/* .header = */ NULL,
	/* .flags =  */ pdff_psbend
};

const struct pt_decoder_function pt_decode_tsc = {
	/* .packet = */ pt_pkt_decode_tsc,
	/* .decode = */ pt_qry_decode_tsc,
	/* .header = */ pt_qry_decode_tsc,
	/* .flags =  */ 0
};

const struct pt_decoder_function pt_decode_cbr = {
	/* .packet = */ pt_pkt_decode_cbr,
	/* .decode = */ pt_qry_decode_cbr,
	/* .header = */ pt_qry_decode_cbr,
	/* .flags =  */ 0
};

int pt_fetch_decoder(struct pt_decoder *decoder)
{
	const uint8_t *pos, *begin, *end;
	uint8_t opc, ext;

	if (!decoder)
		return -pte_internal;

	/* Clear the decoder's decode function in case of errors. */
	decoder->next = NULL;

	begin = pt_begin(decoder);
	end = pt_end(decoder);
	pos = decoder->pos;

	if (!pos || (pos < begin) || (end < pos))
		return -pte_nosync;

	if (pos == end)
		return -pte_eos;

	opc = *pos++;
	switch (opc) {
	default:
		/* Check opcodes that require masking. */
		if ((opc & pt_opm_tnt_8) == pt_opc_tnt_8) {
			decoder->next = &pt_decode_tnt_8;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip) {
			decoder->next = &pt_decode_tip;
			return 0;
		}

		if ((opc & pt_opm_fup) == pt_opc_fup) {
			decoder->next = &pt_decode_fup;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip_pge) {
			decoder->next = &pt_decode_tip_pge;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip_pgd) {
			decoder->next = &pt_decode_tip_pgd;
			return 0;
		}

		decoder->next = &pt_decode_unknown;
		return 0;

	case pt_opc_pad:
		decoder->next = &pt_decode_pad;
		return 0;

	case pt_opc_mode:
		decoder->next = &pt_decode_mode;
		return 0;

	case pt_opc_tsc:
		decoder->next = &pt_decode_tsc;
		return 0;

	case pt_opc_ext:
		if (pos == end)
			return -pte_eos;

		ext = *pos++;
		switch (ext) {
		default:
			decoder->next = &pt_decode_unknown;
			return 0;

		case pt_ext_psb:
			decoder->next = &pt_decode_psb;
			return 0;

		case pt_ext_ovf:
			decoder->next = &pt_decode_ovf;
			return 0;

		case pt_ext_tnt_64:
			decoder->next = &pt_decode_tnt_64;
			return 0;

		case pt_ext_psbend:
			decoder->next = &pt_decode_psbend;
			return 0;

		case pt_ext_cbr:
			decoder->next = &pt_decode_cbr;
			return 0;

		case pt_ext_pip:
			decoder->next = &pt_decode_pip;
			return 0;
		}
	}
}
