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

#include "pt_decoder_fixture.h"
#include "suites.h"

#include "pt_packet_decode.h"
#include "pt_decoder.h"

#include <check.h>


START_TEST(check_decode_null)
{
	int errcode;

	errcode = pt_fetch_decoder(NULL);
	ck_int_eq(errcode, -pte_internal);
}
END_TEST

START_TEST(check_decode_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	config->end = config->begin;
	decoder->pos = config->begin;

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_null(decoder->next);
	ck_ptr(decoder->pos, config->begin);
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->flags, 0);
	ck_uint64_eq(decoder->tsc, 0);

	ck_last_ip();
	ck_tnt_cache();
}
END_TEST

START_TEST(check_flags)
{
	ck_int_eq(pt_decode_unknown.flags, pdff_unknown);
	ck_int_eq(pt_decode_pad.flags, 0);
	ck_int_eq(pt_decode_psb.flags, 0);
	ck_int_eq(pt_decode_tip.flags, pdff_tip);
	ck_int_eq(pt_decode_tnt_8.flags, pdff_tnt);
	ck_int_eq(pt_decode_tnt_64.flags, pdff_tnt);
	ck_int_eq(pt_decode_tip_pge.flags, pdff_event);
	ck_int_eq(pt_decode_tip_pgd.flags, pdff_event);
	ck_int_eq(pt_decode_fup.flags, pdff_fup);
	ck_int_eq(pt_decode_pip.flags, pdff_event);
	ck_int_eq(pt_decode_ovf.flags, pdff_psbend);
	ck_int_eq(pt_decode_mode.flags, pdff_event);
	ck_int_eq(pt_decode_psbend.flags, pdff_psbend);
	ck_int_eq(pt_decode_tsc.flags, 0);
	ck_int_eq(pt_decode_cbr.flags, 0);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when fetching
 * a decoder function.
 */
static void check_non_fetch_state(struct pt_decoder *decoder)
{
	ck_ptr(decoder->pos, decoder->config.begin);
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->flags, 0);
	ck_uint64_eq(decoder->tsc, 0);

	ck_last_ip();
	ck_tnt_cache();
}

START_TEST(check_fetch_unknown)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	*encoder->pos++ = pt_opc_bad;

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_unknown);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_ext_unknown)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	*encoder->pos++ = pt_opc_ext;
	*encoder->pos++ = pt_ext_bad;

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_unknown);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_pad)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_pad(encoder);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_pad);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_psb)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_psb(encoder);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_psb);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_psbend)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_psbend(encoder);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_psbend);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tip)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tip(encoder, 0, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tip);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tip_pge)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tip_pge(encoder, 0, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tip_pge);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tip_pgd)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tip_pgd(encoder, 0, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tip_pgd);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_fup)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_fup(encoder, 0, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_fup);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tnt_8)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tnt_8(encoder, 0, 1);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tnt_8);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tnt_64)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tnt_64(encoder, 0, 1);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tnt_64);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_pip)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_pip(encoder, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_pip);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_ovf)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_ovf(encoder);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_ovf);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_mode_exec)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_mode_exec(encoder, ptem_64bit);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_mode);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_mode_tsx)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_mode);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_tsc(encoder, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_tsc);

	check_non_fetch_state(decoder);
}
END_TEST

START_TEST(check_fetch_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_cbr(encoder, 0);

	errcode = pt_fetch_decoder(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->next, &pt_decode_cbr);

	check_non_fetch_state(decoder);
}
END_TEST

/* Check that the state is essentially blank, except for flags, which typically
 * need to be preserved.
 */
static void check_blank_state(struct pt_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_event_pending(decoder, evb_psbend));
	ck_false(pt_event_pending(decoder, evb_tip));
	ck_false(pt_event_pending(decoder, evb_fup));

	ck_last_ip();
	ck_tnt_cache();
}

static int decode_unknown_skip_4(struct pt_packet_unknown *unknown,
				 const struct pt_config *config,
				 const uint8_t *pos, void *context)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;

	ck_nonnull(unknown);
	ck_ptr(config, &decoder->config);
	ck_ptr(pos, decoder->pos);
	ck_ptr(unknown->packet, decoder->pos);
	ck_ptr(unknown->priv, NULL);
	ck_ptr(context, dfix);

	return 4;
}

static int decode_unknown_nomem(struct pt_packet_unknown *unknown,
				const struct pt_config *config,
				const uint8_t *pos, void *context)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;

	ck_nonnull(unknown);
	ck_ptr(config, &decoder->config);
	ck_ptr(pos, decoder->pos);
	ck_ptr(context, NULL);

	return -pte_nomem;
}

START_TEST(check_packet_unknown_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	errcode = pt_decode_unknown.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_bad_opc);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_unknown_skip_4)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	config->decode.callback = decode_unknown_skip_4;
	config->decode.context = dfix;

	errcode = pt_decode_unknown.packet(&packet, decoder);
	ck_int_eq(errcode, 4);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_unknown);
	ck_uint_eq(packet.size, 4);
	ck_ptr(packet.payload.unknown.packet, encoder->pos);
	ck_null(packet.payload.unknown.priv);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_unknown_nomem_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	config->decode.callback = decode_unknown_nomem;

	errcode = pt_decode_unknown.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_nomem);
	ck_ptr(decoder->pos, encoder->pos);

	ck_ptr(packet.payload.unknown.packet, encoder->pos);
	ck_null(packet.payload.unknown.priv);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_pad)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_pad(encoder);

	errcode = pt_decode_pad.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_pad);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_pad);
	ck_uint_eq(packet.size, ptps_pad);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_psb)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_psb(encoder);

	errcode = pt_decode_psb.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_psb);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_psb);
	ck_uint_eq(packet.size, ptps_psb);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_psb_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_psb(encoder);

	config->end = encoder->pos - 1;

	errcode = pt_decode_psb.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_psb_fault_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_psb(encoder);

	encoder->pos[-3] = 0xffull;

	errcode = pt_decode_psb.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	errcode = pt_decode_tip.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_supp);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip);
	ck_uint_eq(packet.size, ptps_tip_supp);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_suppressed);
	ck_uint64_eq(packet.payload.ip.ip, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecdull;
	int errcode;

	check_encode_tip(encoder, ip, pt_ipc_update_16);

	errcode = pt_decode_tip.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_upd16);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip);
	ck_uint_eq(packet.size, ptps_tip_upd16);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_16);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecd83abull;
	int errcode;

	check_encode_tip(encoder, ip, pt_ipc_update_32);

	errcode = pt_decode_tip.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_upd32);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip);
	ck_uint_eq(packet.size, ptps_tip_upd32);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_32);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = pt_dfix_max_ip;
	int errcode;

	check_encode_tip(encoder, ip, pt_ipc_sext_48);

	errcode = pt_decode_tip.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_sext48);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip);
	ck_uint_eq(packet.size, ptps_tip_sext48);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_sext_48);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tnt_8)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint8_t tnt = 0xc, size = 5;
	int errcode;

	check_encode_tnt_8(encoder, tnt, size);

	errcode = pt_decode_tnt_8.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tnt_8);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tnt_8);
	ck_uint_eq(packet.size, ptps_tnt_8);
	ck_int_eq(packet.payload.tnt.bit_size, size);
	ck_uint64_eq(packet.payload.tnt.payload, tnt);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tnt_8_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tnt_8(encoder, 0, 0);

	errcode = pt_decode_tnt_8.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tnt_64)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint8_t tnt = 0xc, size = 4;
	int errcode;

	check_encode_tnt_64(encoder, tnt, size);

	errcode = pt_decode_tnt_64.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tnt_64);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tnt_64);
	ck_uint_eq(packet.size, ptps_tnt_64);
	ck_int_eq(packet.payload.tnt.bit_size, size);
	ck_uint64_eq(packet.payload.tnt.payload, tnt);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tnt_64_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tnt_64(encoder, 0, 0);

	errcode = pt_decode_tnt_64.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pge_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip_pge(encoder, 0, pt_ipc_suppressed);

	errcode = pt_decode_tip_pge.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pge_supp);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pge);
	ck_uint_eq(packet.size, ptps_tip_pge_supp);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_suppressed);
	ck_uint64_eq(packet.payload.ip.ip, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pge_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecdull;
	int errcode;

	check_encode_tip_pge(encoder, ip, pt_ipc_update_16);

	errcode = pt_decode_tip_pge.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pge_upd16);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pge);
	ck_uint_eq(packet.size, ptps_tip_pge_upd16);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_16);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pge_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecd83abull;
	int errcode;

	check_encode_tip_pge(encoder, ip, pt_ipc_update_32);

	errcode = pt_decode_tip_pge.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pge_upd32);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pge);
	ck_uint_eq(packet.size, ptps_tip_pge_upd32);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_32);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pge_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = pt_dfix_max_ip;
	int errcode;

	check_encode_tip_pge(encoder, ip, pt_ipc_sext_48);

	errcode = pt_decode_tip_pge.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pge_sext48);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pge);
	ck_uint_eq(packet.size, ptps_tip_pge_sext48);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_sext_48);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pge_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip_pge(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip_pge.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pgd_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);

	errcode = pt_decode_tip_pgd.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pgd_supp);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pgd);
	ck_uint_eq(packet.size, ptps_tip_pgd_supp);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_suppressed);
	ck_uint64_eq(packet.payload.ip.ip, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pgd_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecdull;
	int errcode;

	check_encode_tip_pgd(encoder, ip, pt_ipc_update_16);

	errcode = pt_decode_tip_pgd.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pgd_upd16);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pgd);
	ck_uint_eq(packet.size, ptps_tip_pgd_upd16);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_16);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pgd_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecd83abull;
	int errcode;

	check_encode_tip_pgd(encoder, ip, pt_ipc_update_32);

	errcode = pt_decode_tip_pgd.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pgd_upd32);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pgd);
	ck_uint_eq(packet.size, ptps_tip_pgd_upd32);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_32);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pgd_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = pt_dfix_max_ip;
	int errcode;

	check_encode_tip_pgd(encoder, ip, pt_ipc_sext_48);

	errcode = pt_decode_tip_pgd.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tip_pgd_sext48);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tip_pgd);
	ck_uint_eq(packet.size, ptps_tip_pgd_sext48);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_sext_48);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tip_pgd_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tip_pgd(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip_pgd.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_fup_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_suppressed);

	errcode = pt_decode_fup.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_fup_supp);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_fup);
	ck_uint_eq(packet.size, ptps_fup_supp);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_suppressed);
	ck_uint64_eq(packet.payload.ip.ip, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_fup_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecdull;
	int errcode;

	check_encode_fup(encoder, ip, pt_ipc_update_16);

	errcode = pt_decode_fup.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_fup_upd16);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_fup);
	ck_uint_eq(packet.size, ptps_fup_upd16);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_16);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_fup_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = 0xfecd83abull;
	int errcode;

	check_encode_fup(encoder, ip, pt_ipc_update_32);

	errcode = pt_decode_fup.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_fup_upd32);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_fup);
	ck_uint_eq(packet.size, ptps_fup_upd32);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_update_32);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t ip = pt_dfix_max_ip;
	int errcode;

	check_encode_fup(encoder, ip, pt_ipc_sext_48);

	errcode = pt_decode_fup.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_fup_sext48);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_fup);
	ck_uint_eq(packet.size, ptps_fup_sext48);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_sext_48);
	ck_uint64_eq(packet.payload.ip.ip, ip);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	errcode = pt_decode_fup.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_pip)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_pip(encoder, cr3);

	errcode = pt_decode_pip.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_pip);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_pip);
	ck_uint_eq(packet.size, ptps_pip);
	ck_int_eq(packet.payload.pip.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_pip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_pip(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_pip.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_ovf)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_ovf(encoder);

	errcode = pt_decode_ovf.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_ovf);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_ovf);
	ck_uint_eq(packet.size, ptps_ovf);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_exec_16bit)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_exec);
	ck_uint_eq(packet.payload.mode.bits.exec.csl, 0);
	ck_uint_eq(packet.payload.mode.bits.exec.csd, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_exec_32bit)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_exec(encoder, ptem_32bit);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_exec);
	ck_uint_eq(packet.payload.mode.bits.exec.csl, 0);
	ck_uint_eq(packet.payload.mode.bits.exec.csd, 1);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_exec_64bit)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_exec(encoder, ptem_64bit);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_exec);
	ck_uint_eq(packet.payload.mode.bits.exec.csl, 1);
	ck_uint_eq(packet.payload.mode.bits.exec.csd, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_exec_unknown)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);

	encoder->pos[-1] |= pt_mob_exec_csl | pt_mob_exec_csd;

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_exec);
	ck_uint_eq(packet.payload.mode.bits.exec.csl, 1);
	ck_uint_eq(packet.payload.mode.bits.exec.csd, 1);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_tsx_xbegin)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_tsx);
	ck_uint_eq(packet.payload.mode.bits.tsx.intx, 1);
	ck_uint_eq(packet.payload.mode.bits.tsx.abrt, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_tsx_xend)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_tsx);
	ck_uint_eq(packet.payload.mode.bits.tsx.intx, 0);
	ck_uint_eq(packet.payload.mode.bits.tsx.abrt, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_mode_tsx_xabort)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);

	errcode = pt_decode_mode.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_tsx);
	ck_uint_eq(packet.payload.mode.bits.tsx.intx, 0);
	ck_uint_eq(packet.payload.mode.bits.tsx.abrt, 1);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_psbend)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_psbend(encoder);

	errcode = pt_decode_psbend.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_psbend);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_psbend);
	ck_uint_eq(packet.size, ptps_psbend);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint64_t tsc = 0x11223344556677;
	int errcode;

	check_encode_tsc(encoder, tsc);

	errcode = pt_decode_tsc.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_tsc);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_tsc);
	ck_uint_eq(packet.size, ptps_tsc);
	ck_uint64_eq(packet.payload.tsc.tsc, tsc);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_tsc_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_tsc(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tsc.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	uint8_t cbr = 0x4;
	int errcode;

	check_encode_cbr(encoder, cbr);

	errcode = pt_decode_cbr.packet(&packet, decoder);
	ck_int_eq(errcode, ptps_cbr);
	ck_ptr(decoder->pos, config->begin);

	ck_int_eq(packet.type, ppt_cbr);
	ck_uint_eq(packet.size, ptps_cbr);
	ck_uint64_eq(packet.payload.cbr.ratio, cbr);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_packet_cbr_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet packet;
	int errcode;

	check_encode_cbr(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_cbr.packet(&packet, decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_unknown_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	errcode = pt_decode_unknown.header(decoder);
	ck_int_eq(errcode, -pte_bad_opc);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_unknown_skip_4)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	config->decode.callback = decode_unknown_skip_4;
	config->decode.context = dfix;

	errcode = pt_decode_unknown.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos + 4);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_unknown_nomem_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	config->decode.callback = decode_unknown_nomem;

	errcode = pt_decode_unknown.header(decoder);
	ck_int_eq(errcode, -pte_nomem);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_pad)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_pad(encoder);

	errcode = pt_decode_pad.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_psb)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	const uint8_t *sync;
	int errcode;

	check_encode_psb(encoder);

	sync = decoder->sync;

	errcode = pt_decode_psb.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->sync, sync);
}
END_TEST

START_TEST(check_header_psb_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psb(encoder);

	config->end = encoder->pos - 1;

	errcode = pt_decode_psb.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_psb_fault_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psb(encoder);

	encoder->pos[-3] = 0xffull;

	errcode = pt_decode_psb.header(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when decoding
 * FUP in header context.
 */
static void check_header_non_fup_state(struct pt_decoder *decoder)
{
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->tsc, 0);

	ck_false(pt_event_pending(decoder, evb_psbend));
	ck_false(pt_event_pending(decoder, evb_tip));
	ck_false(pt_event_pending(decoder, evb_fup));

	ck_tnt_cache();
}

START_TEST(check_header_fup_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	uint64_t flags = decoder->flags;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_last_ip();

	check_header_non_fup_state(decoder);
}
END_TEST

START_TEST(check_header_fup_update_16_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_update_16);

	errcode = pt_decode_fup.header(decoder);
	ck_int_eq(errcode, -pte_noip);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_last_ip();

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_fup_update_32_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_update_32);

	errcode = pt_decode_fup.header(decoder);
	ck_int_eq(errcode, -pte_noip);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_last_ip();

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_status_have_ip);
	ck_last_ip();

	check_header_non_fup_state(decoder);
}
END_TEST

START_TEST(check_header_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_update_32);

	config->end = encoder->pos - 1;

	errcode = pt_decode_fup.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_last_ip();

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_pip)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_max_cr3, flags = decoder->flags;
	int errcode;

	check_encode_pip(encoder, cr3);

	errcode = pt_decode_pip.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	event = pt_dequeue_event(decoder, evb_psbend);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_paging);
	ck_uint64_eq(event->variant.paging.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_pip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_pip(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_pip.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_mode_exec)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_64bit;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_exec(encoder, mode);

	errcode = pt_decode_mode.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	event = pt_dequeue_event(decoder, evb_psbend);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, mode);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_mode_exec_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);

	config->end = encoder->pos - 1;

	errcode = pt_decode_mode.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_mode_tsx)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	errcode = pt_decode_mode.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	event = pt_dequeue_event(decoder, evb_psbend);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_tsx);
	ck_int_eq(event->variant.tsx.speculative, 1);
	ck_int_eq(event->variant.tsx.aborted, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_mode_tsx_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_mode.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when decoding
 * timing related packets.
 */
static void check_non_timing_state(struct pt_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_event_pending(decoder, evb_psbend));
	ck_false(pt_event_pending(decoder, evb_tip));
	ck_false(pt_event_pending(decoder, evb_fup));

	ck_last_ip();
	ck_tnt_cache();
}

START_TEST(check_header_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t tsc = 0x11223344556677;
	int errcode;

	check_encode_tsc(encoder, tsc);

	errcode = pt_decode_tsc.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->tsc, tsc);

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_header_tsc_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_tsc(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tsc.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode;

	check_encode_cbr(encoder, 0);

	errcode = pt_decode_cbr.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->tsc, 0);

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_header_cbr_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_cbr(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_cbr.header(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_unknown_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	errcode = pt_decode_unknown.decode(decoder);
	ck_int_eq(errcode, -pte_bad_opc);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_unknown_skip_4)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	config->decode.callback = decode_unknown_skip_4;
	config->decode.context = dfix;

	errcode = pt_decode_unknown.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos + 4);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_unknown_nomem_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	config->decode.callback = decode_unknown_nomem;

	errcode = pt_decode_unknown.decode(decoder);
	ck_int_eq(errcode, -pte_nomem);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_pad)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_pad(encoder);

	errcode = pt_decode_pad.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_psb)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	const uint8_t *pos, *sync;
	int errcode;

	pos = check_encode_psb(encoder);
	check_encode_psbend(encoder);

	sync = decoder->sync;

	errcode = pt_decode_psb.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, pos);
	ck_ptr(decoder->sync, sync);
}
END_TEST

START_TEST(check_decode_psb_ovf)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	const uint8_t *pos, *sync;
	int errcode;

	pos = check_encode_psb(encoder);
	check_encode_ovf(encoder);

	sync = decoder->sync;

	errcode = pt_decode_psb.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, pos);
	ck_ptr(decoder->sync, sync);
}
END_TEST

START_TEST(check_decode_psb_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psb(encoder);

	config->end = encoder->pos - 1;

	errcode = pt_decode_psb.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_psb_fault_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psb(encoder);

	encoder->pos[-3] = 0xffull;

	errcode = pt_decode_psb.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when decoding
 * an IP changing packet.
 */
static void check_non_ip_state(struct pt_decoder *decoder)
{
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->tsc, 0);

	ck_false(pt_event_pending(decoder, evb_psbend));
	ck_false(pt_event_pending(decoder, evb_tip));
	ck_false(pt_event_pending(decoder, evb_fup));

	ck_tnt_cache();
}

START_TEST(check_decode_tip_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_tip(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_exec_mode)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	enum pt_exec_mode mode = ptem_32bit;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_uint64_eq(decoder->event->variant.exec_mode.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_exec_mode_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_async_branch)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_async_branch;
	event->variant.async_branch.from = at;

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_branch);
	ck_uint64_eq(decoder->event->variant.async_branch.from, at);
	ck_uint64_eq(decoder->event->variant.async_branch.to, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_async_branch_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_async_branch;
	event->variant.async_branch.from = at;

	errcode = pt_decode_tip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_branch);
	ck_uint64_eq(decoder->event->variant.async_branch.from, at);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when decoding
 * a TNT packet.
 */
static void check_non_tnt_state(struct pt_decoder *decoder)
{
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->flags, 0);
	ck_uint64_eq(decoder->tsc, 0);

	ck_false(pt_event_pending(decoder, evb_psbend));
	ck_false(pt_event_pending(decoder, evb_tip));
	ck_false(pt_event_pending(decoder, evb_fup));

	ck_last_ip();
}

START_TEST(check_decode_tnt_8)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_tnt packet;
	int errcode;

	packet.bit_size = 5;
	packet.payload = 0xc;
	pt_tnt_cache_update_tnt(&dfix->tnt, &packet, &dfix->config);

	check_encode_tnt_8(encoder, packet.payload, packet.bit_size);

	errcode = pt_decode_tnt_8.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_tnt_cache();

	check_non_tnt_state(decoder);
}
END_TEST

START_TEST(check_decode_tnt_8_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_tnt_8(encoder, 0, 0);

	errcode = pt_decode_tnt_8.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_tnt_cache();

	check_non_tnt_state(decoder);
}
END_TEST

START_TEST(check_decode_tnt_64)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_tnt packet;
	int errcode;

	packet.bit_size = 12;
	packet.payload = 0xc;
	pt_tnt_cache_update_tnt(&dfix->tnt, &packet, &dfix->config);

	check_encode_tnt_64(encoder, packet.payload, packet.bit_size);

	errcode = pt_decode_tnt_64.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_tnt_cache();

	check_non_tnt_state(decoder);
}
END_TEST

START_TEST(check_decode_tnt_64_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_tnt_64(encoder, 0, 0);

	errcode = pt_decode_tnt_64.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_tnt_cache();

	check_non_tnt_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_enabled);
	ck_uint64_eq(decoder->event->variant.enabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_enabled);
	ck_uint64_eq(decoder->event->variant.enabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_enabled);
	ck_uint64_eq(decoder->event->variant.enabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_tip_pge(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_event)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event, *ev;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xdccdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, pdf_consume_packet);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_enabled);
	ck_uint64_eq(decoder->event->variant.enabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	ev = pt_dequeue_event(decoder, evb_tip);
	ck_ptr(ev, event);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_event_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event, *ev;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	ev = pt_dequeue_event(decoder, evb_tip);
	ck_ptr(ev, event);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_overflow)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_overflow;

	decoder->flags |= pdf_consume_packet;
	decoder->flags &= ~pdf_pt_disabled;

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_overflow);
	ck_uint64_eq(decoder->event->variant.overflow.ip, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_overflow_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_overflow;

	decoder->flags |= pdf_consume_packet;
	decoder->flags &= ~pdf_pt_disabled;

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_exec_mode)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_16bit;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	decoder->flags |= pdf_consume_packet;
	decoder->flags &= ~pdf_pt_disabled;

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_uint64_eq(decoder->event->variant.exec_mode.ip, dfix->last_ip.ip);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_exec_mode_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_64bit;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	decoder->flags |= pdf_consume_packet;
	decoder->flags &= ~pdf_pt_disabled;

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_disabled);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_disabled);
	ck_uint64_eq(decoder->event->variant.disabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_disabled);
	ck_uint64_eq(decoder->event->variant.disabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_disabled);
	ck_uint64_eq(decoder->event->variant.disabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_async_branch)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_async_branch;
	event->variant.async_branch.from = at;

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_disabled);
	ck_uint64_eq(decoder->event->variant.async_disabled.at, at);
	ck_uint64_eq(decoder->event->variant.async_disabled.ip,
		     dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pgd_async_branch_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_async_branch;
	event->variant.async_branch.from = at;

	errcode = pt_decode_tip_pgd.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_disabled);
	ck_uint64_eq(decoder->event->variant.async_disabled.at, at);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_last_ip();

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_overflow)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_overflow;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_overflow);
	ck_uint64_eq(decoder->event->variant.overflow.ip, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_overflow_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_overflow;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_tsx)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 1;
	event->variant.tsx.aborted = 0;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 1);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);
	ck_uint64_eq(decoder->event->variant.tsx.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_tsx_abort)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 0;
	event->variant.tsx.aborted = 1;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 1);
	ck_uint64_eq(decoder->event->variant.tsx.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_tsx_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 1;
	event->variant.tsx.aborted = 0;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 1);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_tsx_abort_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 0;
	event->variant.tsx.aborted = 1;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 1);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_tsx_abort_consume)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_enqueue_event(decoder, evb_fup);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 0;
	event->variant.tsx.aborted = 1;

	decoder->flags |= pdf_consume_packet;

	errcode = pt_decode_fup.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 1);
	ck_uint64_eq(decoder->event->variant.tsx.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_pip)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_pip(encoder, cr3);

	errcode = pt_decode_pip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_paging);
	ck_uint64_eq(decoder->event->variant.paging.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_pip_async_branch)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_pip(encoder, cr3);

	event = pt_enqueue_event(decoder, evb_tip);
	event->type = ptev_async_branch;

	errcode = pt_decode_pip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_null(decoder->event);

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_paging);
	ck_uint64_eq(event->variant.async_paging.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_pip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_pip(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_pip.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

/* Check aspects of the decoder state that should not be modified when decoding
 * a state resetting, event queueing packet.
 */
static void check_clean_state(struct pt_decoder *decoder)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;

	ck_null(decoder->sync);
	ck_uint64_eq(decoder->tsc, 0);

	pt_last_ip_init(&dfix->last_ip);
	ck_last_ip();

	pt_tnt_cache_init(&dfix->tnt);
	ck_tnt_cache();
}

START_TEST(check_decode_ovf)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_ovf(encoder);

	decoder->tnt.tnt = 0x7fffffffffffffffull;
	decoder->tnt.index = 0x8000000000000000ull;

	errcode = pt_decode_ovf.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, 0);

	event = pt_dequeue_event(decoder, evb_fup);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_overflow);

	check_clean_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_disabled)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_ovf(encoder);

	decoder->flags = pdf_pt_disabled;
	decoder->tnt.tnt = 0x7fffffffffffffffull;
	decoder->tnt.index = 0x8000000000000000ull;

	errcode = pt_decode_ovf.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, pdf_pt_disabled);

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_overflow);

	check_clean_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_psbend_paging)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_bad_cr3;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_paging;
	event->variant.paging.cr3 = cr3;

	errcode = pt_decode_ovf.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_paging);
	ck_uint64_eq(decoder->event->variant.async_paging.cr3, cr3);
	ck_uint64_eq(decoder->event->variant.async_paging.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_psbend_exec_mode)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_32bit;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	errcode = pt_decode_ovf.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_uint64_eq(decoder->event->variant.exec_mode.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_psbend_tsx)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 0;
	event->variant.tsx.aborted = 0;

	errcode = pt_decode_ovf.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);
	ck_uint64_eq(decoder->event->variant.tsx.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_exec)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_16bit;
	int errcode;

	check_encode_mode_exec(encoder, mode);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, mode);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_exec_fault)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);

	encoder->pos[-1] |= pt_mob_exec_csl | pt_mob_exec_csd;

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_dequeue_event(decoder, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, ptem_unknown);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xbegin)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_dequeue_event(decoder, evb_fup);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_tsx);
	ck_int_eq(event->variant.tsx.speculative, 1);
	ck_int_eq(event->variant.tsx.aborted, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xend)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_dequeue_event(decoder, evb_fup);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_tsx);
	ck_int_eq(event->variant.tsx.speculative, 0);
	ck_int_eq(event->variant.tsx.aborted, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xabort)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_dequeue_event(decoder, evb_fup);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_tsx);
	ck_int_eq(event->variant.tsx.speculative, 0);
	ck_int_eq(event->variant.tsx.aborted, 1);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xbegin_disabled)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	decoder->flags |= pdf_pt_disabled;

	flags |= pdf_pt_disabled;

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 1);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xend_disabled)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	decoder->flags |= pdf_pt_disabled;

	flags |= pdf_pt_disabled;

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xabort_disabled)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);

	decoder->flags |= pdf_pt_disabled;

	flags |= pdf_pt_disabled;

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 1);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_psbend)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	errcode = pt_decode_psbend.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_psbend_paging)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_bad_cr3;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_paging;
	event->variant.paging.cr3 = cr3;

	errcode = pt_decode_psbend.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_async_paging);
	ck_uint64_eq(decoder->event->variant.async_paging.cr3, cr3);
	ck_uint64_eq(decoder->event->variant.async_paging.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_psbend_exec_mode)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_32bit;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = mode;

	errcode = pt_decode_psbend.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_exec_mode);
	ck_int_eq(decoder->event->variant.exec_mode.mode, mode);
	ck_uint64_eq(decoder->event->variant.exec_mode.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_psbend_tsx)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_enqueue_event(decoder, evb_psbend);
	event->type = ptev_tsx;
	event->variant.tsx.speculative = 0;
	event->variant.tsx.aborted = 0;

	errcode = pt_decode_psbend.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_ptr(decoder->event, event);
	ck_int_eq(decoder->event->type, ptev_tsx);
	ck_int_eq(decoder->event->variant.tsx.speculative, 0);
	ck_int_eq(decoder->event->variant.tsx.aborted, 0);
	ck_uint64_eq(decoder->event->variant.tsx.ip, dfix->last_ip.ip);
	ck_last_ip();

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t tsc = 0x11223344556677, flags = decoder->flags;
	int errcode;

	check_encode_tsc(encoder, tsc);

	errcode = pt_decode_tsc.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(decoder->flags, flags);
	ck_uint64_eq(decoder->tsc, tsc);

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_tsc_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t tsc = 0x11223344556677, flags = decoder->flags;
	int errcode;

	check_encode_tsc(encoder, 0);

	config->end = encoder->pos - 1;
	decoder->tsc = tsc;

	errcode = pt_decode_tsc.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_uint64_eq(decoder->flags, flags);
	ck_uint64_eq(decoder->tsc, tsc);

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_cbr(encoder, 0);

	errcode = pt_decode_cbr.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(decoder->flags, flags);

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_cbr_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_cbr(encoder, 0);

	config->end = encoder->pos - 1;

	errcode = pt_decode_cbr.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_uint64_eq(decoder->flags, flags);

	check_non_timing_state(decoder);
}
END_TEST

static void add_simple_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_decode_null);
	tcase_add_test(tcase, check_decode_empty);
	tcase_add_test(tcase, check_flags);
}

static void add_fetch_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_fetch_unknown);
	tcase_add_test(tcase, check_fetch_ext_unknown);
	tcase_add_test(tcase, check_fetch_pad);
	tcase_add_test(tcase, check_fetch_psb);
	tcase_add_test(tcase, check_fetch_psbend);
	tcase_add_test(tcase, check_fetch_tip);
	tcase_add_test(tcase, check_fetch_tip_pge);
	tcase_add_test(tcase, check_fetch_tip_pgd);
	tcase_add_test(tcase, check_fetch_fup);
	tcase_add_test(tcase, check_fetch_tnt_8);
	tcase_add_test(tcase, check_fetch_tnt_64);
	tcase_add_test(tcase, check_fetch_pip);
	tcase_add_test(tcase, check_fetch_ovf);
	tcase_add_test(tcase, check_fetch_mode_exec);
	tcase_add_test(tcase, check_fetch_mode_tsx);
	tcase_add_test(tcase, check_fetch_tsc);
	tcase_add_test(tcase, check_fetch_cbr);
}

static void add_packet_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_packet_unknown_fail);
	tcase_add_test(tcase, check_packet_unknown_skip_4);
	tcase_add_test(tcase, check_packet_unknown_nomem_fail);

	tcase_add_test(tcase, check_packet_pad);

	tcase_add_test(tcase, check_packet_psb);
	tcase_add_test(tcase, check_packet_psb_cutoff_fail);
	tcase_add_test(tcase, check_packet_psb_fault_fail);

	tcase_add_test(tcase, check_packet_tip_suppressed);
	tcase_add_test(tcase, check_packet_tip_update_16);
	tcase_add_test(tcase, check_packet_tip_update_32);
	tcase_add_test(tcase, check_packet_tip_sext_48);
	tcase_add_test(tcase, check_packet_tip_cutoff_fail);

	tcase_add_test(tcase, check_packet_tnt_8);
	tcase_add_test(tcase, check_packet_tnt_8_fail);
	tcase_add_test(tcase, check_packet_tnt_64);
	tcase_add_test(tcase, check_packet_tnt_64_fail);

	tcase_add_test(tcase, check_packet_tip_pge_suppressed);
	tcase_add_test(tcase, check_packet_tip_pge_update_16);
	tcase_add_test(tcase, check_packet_tip_pge_update_32);
	tcase_add_test(tcase, check_packet_tip_pge_sext_48);
	tcase_add_test(tcase, check_packet_tip_pge_cutoff_fail);

	tcase_add_test(tcase, check_packet_tip_pgd_suppressed);
	tcase_add_test(tcase, check_packet_tip_pgd_update_16);
	tcase_add_test(tcase, check_packet_tip_pgd_update_32);
	tcase_add_test(tcase, check_packet_tip_pgd_sext_48);
	tcase_add_test(tcase, check_packet_tip_pgd_cutoff_fail);

	tcase_add_test(tcase, check_packet_fup_suppressed);
	tcase_add_test(tcase, check_packet_fup_update_16);
	tcase_add_test(tcase, check_packet_fup_update_32);
	tcase_add_test(tcase, check_packet_fup_sext_48);
	tcase_add_test(tcase, check_packet_fup_cutoff_fail);

	tcase_add_test(tcase, check_packet_pip);
	tcase_add_test(tcase, check_packet_pip_cutoff_fail);

	tcase_add_test(tcase, check_packet_ovf);

	tcase_add_test(tcase, check_packet_mode_exec_16bit);
	tcase_add_test(tcase, check_packet_mode_exec_32bit);
	tcase_add_test(tcase, check_packet_mode_exec_64bit);
	tcase_add_test(tcase, check_packet_mode_exec_unknown);

	tcase_add_test(tcase, check_packet_mode_tsx_xbegin);
	tcase_add_test(tcase, check_packet_mode_tsx_xend);
	tcase_add_test(tcase, check_packet_mode_tsx_xabort);

	tcase_add_test(tcase, check_packet_psbend);

	tcase_add_test(tcase, check_packet_tsc);
	tcase_add_test(tcase, check_packet_tsc_cutoff_fail);

	tcase_add_test(tcase, check_packet_cbr);
	tcase_add_test(tcase, check_packet_cbr_cutoff_fail);
}

static void add_header_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_header_unknown_fail);
	tcase_add_test(tcase, check_header_unknown_skip_4);
	tcase_add_test(tcase, check_header_unknown_nomem_fail);

	tcase_add_test(tcase, check_header_pad);

	tcase_add_test(tcase, check_header_psb);
	tcase_add_test(tcase, check_header_psb_cutoff_fail);
	tcase_add_test(tcase, check_header_psb_fault_fail);

	tcase_add_test(tcase, check_header_fup_suppressed);
	tcase_add_test(tcase, check_header_fup_update_16_fail);
	tcase_add_test(tcase, check_header_fup_update_32_fail);
	tcase_add_test(tcase, check_header_fup_sext_48);
	tcase_add_test(tcase, check_header_fup_cutoff_fail);

	tcase_add_test(tcase, check_header_pip);
	tcase_add_test(tcase, check_header_pip_cutoff_fail);

	tcase_add_test(tcase, check_header_mode_exec);
	tcase_add_test(tcase, check_header_mode_exec_cutoff_fail);

	tcase_add_test(tcase, check_header_mode_tsx);
	tcase_add_test(tcase, check_header_mode_tsx_cutoff_fail);

	tcase_add_test(tcase, check_header_tsc);
	tcase_add_test(tcase, check_header_tsc_cutoff_fail);

	tcase_add_test(tcase, check_header_cbr);
	tcase_add_test(tcase, check_header_cbr_cutoff_fail);
}

static void add_decode_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_decode_unknown_fail);
	tcase_add_test(tcase, check_decode_unknown_skip_4);
	tcase_add_test(tcase, check_decode_unknown_nomem_fail);

	tcase_add_test(tcase, check_decode_pad);

	tcase_add_test(tcase, check_decode_psb);
	tcase_add_test(tcase, check_decode_psb_ovf);
	tcase_add_test(tcase, check_decode_psb_cutoff_fail);
	tcase_add_test(tcase, check_decode_psb_fault_fail);

	tcase_add_test(tcase, check_decode_tip_suppressed);
	tcase_add_test(tcase, check_decode_tip_update_16);
	tcase_add_test(tcase, check_decode_tip_update_32);
	tcase_add_test(tcase, check_decode_tip_sext_48);
	tcase_add_test(tcase, check_decode_tip_cutoff_fail);
	tcase_add_test(tcase, check_decode_tip_exec_mode);
	tcase_add_test(tcase, check_decode_tip_exec_mode_suppressed);
	tcase_add_test(tcase, check_decode_tip_async_branch);
	tcase_add_test(tcase, check_decode_tip_async_branch_suppressed);

	tcase_add_test(tcase, check_decode_tnt_8);
	tcase_add_test(tcase, check_decode_tnt_8_fail);
	tcase_add_test(tcase, check_decode_tnt_64);
	tcase_add_test(tcase, check_decode_tnt_64_fail);

	tcase_add_test(tcase, check_decode_tip_pge_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_update_16);
	tcase_add_test(tcase, check_decode_tip_pge_update_32);
	tcase_add_test(tcase, check_decode_tip_pge_sext_48);
	tcase_add_test(tcase, check_decode_tip_pge_cutoff_fail);
	tcase_add_test(tcase, check_decode_tip_pge_event);
	tcase_add_test(tcase, check_decode_tip_pge_event_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_overflow);
	tcase_add_test(tcase, check_decode_tip_pge_overflow_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_exec_mode);
	tcase_add_test(tcase, check_decode_tip_pge_exec_mode_suppressed);

	tcase_add_test(tcase, check_decode_tip_pgd_suppressed);
	tcase_add_test(tcase, check_decode_tip_pgd_update_16);
	tcase_add_test(tcase, check_decode_tip_pgd_update_32);
	tcase_add_test(tcase, check_decode_tip_pgd_sext_48);
	tcase_add_test(tcase, check_decode_tip_pgd_cutoff_fail);
	tcase_add_test(tcase, check_decode_tip_pgd_async_branch);
	tcase_add_test(tcase, check_decode_tip_pgd_async_branch_suppressed);

	tcase_add_test(tcase, check_decode_fup_suppressed_fail);
	tcase_add_test(tcase, check_decode_fup_update_16);
	tcase_add_test(tcase, check_decode_fup_update_32);
	tcase_add_test(tcase, check_decode_fup_sext_48);
	tcase_add_test(tcase, check_decode_fup_cutoff_fail);
	tcase_add_test(tcase, check_decode_fup_overflow);
	tcase_add_test(tcase, check_decode_fup_overflow_suppressed);
	tcase_add_test(tcase, check_decode_fup_tsx);
	tcase_add_test(tcase, check_decode_fup_tsx_abort);
	tcase_add_test(tcase, check_decode_fup_tsx_suppressed);
	tcase_add_test(tcase, check_decode_fup_tsx_abort_suppressed);
	tcase_add_test(tcase, check_decode_fup_tsx_abort_consume);

	tcase_add_test(tcase, check_decode_pip);
	tcase_add_test(tcase, check_decode_pip_async_branch);
	tcase_add_test(tcase, check_decode_pip_cutoff_fail);

	tcase_add_test(tcase, check_decode_ovf);
	tcase_add_test(tcase, check_decode_ovf_disabled);
	tcase_add_test(tcase, check_decode_ovf_psbend_paging);
	tcase_add_test(tcase, check_decode_ovf_psbend_exec_mode);
	tcase_add_test(tcase, check_decode_ovf_psbend_tsx);

	tcase_add_test(tcase, check_decode_mode_exec);
	tcase_add_test(tcase, check_decode_mode_exec_fault);

	tcase_add_test(tcase, check_decode_mode_tsx_xbegin);
	tcase_add_test(tcase, check_decode_mode_tsx_xend);
	tcase_add_test(tcase, check_decode_mode_tsx_xabort);
	tcase_add_test(tcase, check_decode_mode_tsx_xbegin_disabled);
	tcase_add_test(tcase, check_decode_mode_tsx_xend_disabled);
	tcase_add_test(tcase, check_decode_mode_tsx_xabort_disabled);

	tcase_add_test(tcase, check_decode_psbend);
	tcase_add_test(tcase, check_decode_psbend_paging);
	tcase_add_test(tcase, check_decode_psbend_exec_mode);
	tcase_add_test(tcase, check_decode_psbend_tsx);

	tcase_add_test(tcase, check_decode_tsc);
	tcase_add_test(tcase, check_decode_tsc_cutoff_fail);

	tcase_add_test(tcase, check_decode_cbr);
	tcase_add_test(tcase, check_decode_cbr_cutoff_fail);
}

/* Decode tests that should also pass when pt is disabled. */
static void add_disabled_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_decode_pad);

	tcase_add_test(tcase, check_decode_tip_pge_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_update_16);
	tcase_add_test(tcase, check_decode_tip_pge_update_32);
	tcase_add_test(tcase, check_decode_tip_pge_sext_48);
	tcase_add_test(tcase, check_decode_tip_pge_cutoff_fail);
	tcase_add_test(tcase, check_decode_tip_pge_event);
	tcase_add_test(tcase, check_decode_tip_pge_event_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_overflow);
	tcase_add_test(tcase, check_decode_tip_pge_overflow_suppressed);
	tcase_add_test(tcase, check_decode_tip_pge_exec_mode);
	tcase_add_test(tcase, check_decode_tip_pge_exec_mode_suppressed);

	tcase_add_test(tcase, check_decode_ovf_psbend_paging);
	tcase_add_test(tcase, check_decode_ovf_psbend_exec_mode);
	tcase_add_test(tcase, check_decode_ovf_psbend_tsx);

	tcase_add_test(tcase, check_decode_psbend);
	tcase_add_test(tcase, check_decode_psbend_paging);
	tcase_add_test(tcase, check_decode_psbend_exec_mode);
	tcase_add_test(tcase, check_decode_psbend_tsx);

	tcase_add_test(tcase, check_decode_tsc);
	tcase_add_test(tcase, check_decode_tsc_cutoff_fail);

	tcase_add_test(tcase, check_decode_cbr);
	tcase_add_test(tcase, check_decode_cbr_cutoff_fail);
}

static struct tcase_desc tcase_fetch = {
	/* .name = */ "fetch",
	/* .add_tests = */ add_fetch_tests
};

static struct tcase_desc tcase_packet = {
	/* .name = */ "packet",
	/* .add_tests = */ add_packet_tests
};

static struct tcase_desc tcase_header = {
	/* .name = */ "header",
	/* .add_tests = */ add_header_tests
};

static struct tcase_desc tcase_simple = {
	/* .name = */ "simple",
	/* .add_tests = */ add_simple_tests
};

static struct tcase_desc tcase_decode = {
	/* .name = */ "decode",
	/* .add_tests = */ add_decode_tests
};

static struct tcase_desc tcase_disabled = {
	/* .name = */ "disabled",
	/* .add_tests = */ add_disabled_tests
};

static void pt_dfix_setup_header(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder;

	pt_dfix_setup_standard();

	decoder = dfix->decoder;
	pt_last_ip_init(&decoder->ip);
	pt_last_ip_init(&dfix->last_ip);
}

static void pt_dfix_setup_disabled(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder;

	pt_dfix_setup_standard();

	decoder = dfix->decoder;
	decoder->flags |= pdf_pt_disabled;
}

static struct dfix_desc dfix_header = {
	/* .name = */ "header",
	/* .setup = */ pt_dfix_setup_header
};

static struct dfix_desc dfix_disabled = {
	/* .name = */ "disabled",
	/* .setup = */ pt_dfix_setup_disabled
};

Suite *suite_pt_packet_decode(void)
{
	Suite *suite;

	suite = suite_create("decode");

	pt_add_tcase(suite, &tcase_simple, &dfix_standard);
	pt_add_tcase(suite, &tcase_fetch, &dfix_standard);
	pt_add_tcase(suite, &tcase_packet, &dfix_standard);
	pt_add_tcase(suite, &tcase_header, &dfix_header);
	pt_add_tcase(suite, &tcase_decode, &dfix_standard);
	pt_add_tcase(suite, &tcase_disabled, &dfix_disabled);

	return suite;
}
