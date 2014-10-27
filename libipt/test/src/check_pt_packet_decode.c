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

#include "pt_decoder_function.h"
#include "pt_time.h"

#include <check.h>


/* Check that the state is essentially blank, except for flags, which typically
 * need to be preserved.
 */
static void check_blank_state(struct pt_query_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_evq_pending(&decoder->evq, evb_psbend));
	ck_false(pt_evq_pending(&decoder->evq, evb_tip));
	ck_false(pt_evq_pending(&decoder->evq, evb_fup));

	ck_last_ip();
	ck_tnt_cache();
}

static int decode_unknown_skip_4(struct pt_packet_unknown *unknown,
				 const struct pt_config *config,
				 const uint8_t *pos, void *context)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;

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
	struct pt_query_decoder *decoder = &dfix->decoder;

	ck_nonnull(unknown);
	ck_ptr(config, &decoder->config);
	ck_ptr(pos, decoder->pos);
	ck_ptr(context, NULL);

	return -pte_nomem;
}

START_TEST(check_header_unknown_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
static void check_header_non_fup_state(struct pt_query_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_evq_pending(&decoder->evq, evb_psbend));
	ck_false(pt_evq_pending(&decoder->evq, evb_tip));
	ck_false(pt_evq_pending(&decoder->evq, evb_fup));

	ck_tnt_cache();
	ck_time();
}

START_TEST(check_header_fup_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	ck_last_ip();

	check_header_non_fup_state(decoder);
}
END_TEST

START_TEST(check_header_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_max_cr3, flags = decoder->flags;
	int errcode;

	check_encode_pip(encoder, cr3);

	errcode = pt_decode_pip.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	event = pt_evq_dequeue(&decoder->evq, evb_psbend);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_paging);
	ck_uint64_eq(event->variant.paging.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_pip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_psbend);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, mode);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_mode_exec_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	errcode = pt_decode_mode.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);

	event = pt_evq_dequeue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
static void check_non_timing_state(struct pt_query_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_evq_pending(&decoder->evq, evb_psbend));
	ck_false(pt_evq_pending(&decoder->evq, evb_tip));
	ck_false(pt_evq_pending(&decoder->evq, evb_fup));

	ck_last_ip();
	ck_tnt_cache();
}

START_TEST(check_header_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_time *time = &dfix->time;
	struct pt_packet_tsc packet;
	int errcode;

	packet.tsc = 0xcececeull;

	check_encode_tsc(encoder, packet.tsc);

	errcode = pt_time_update_tsc(time, &packet, config);
	ck_int_eq(errcode, 0);

	errcode = pt_decode_tsc.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_header_tsc_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	ck_time();

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_header_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_time *time = &dfix->time;
	struct pt_packet_cbr packet;
	uint64_t flags = decoder->flags;
	int errcode;

	packet.ratio = 0x38;

	check_encode_cbr(encoder, packet.ratio);

	errcode = pt_time_update_cbr(time, &packet, config);
	ck_int_eq(errcode, 0);

	errcode = pt_decode_cbr.header(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_header_cbr_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_unknown_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
static void check_non_ip_state(struct pt_query_decoder *decoder)
{
	ck_null(decoder->sync);

	ck_false(pt_evq_pending(&decoder->evq, evb_psbend));
	ck_false(pt_evq_pending(&decoder->evq, evb_tip));
	ck_false(pt_evq_pending(&decoder->evq, evb_fup));

	ck_tnt_cache();
	ck_time();
}

START_TEST(check_decode_tip_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
static void check_non_tnt_state(struct pt_query_decoder *decoder)
{
	ck_null(decoder->sync);
	ck_uint64_eq(decoder->flags, 0);

	ck_false(pt_evq_pending(&decoder->evq, evb_psbend));
	ck_false(pt_evq_pending(&decoder->evq, evb_tip));
	ck_false(pt_evq_pending(&decoder->evq, evb_fup));

	ck_last_ip();
	ck_time();
}

START_TEST(check_decode_tnt_8)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event, *ev;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xdccdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, pdf_consume_packet);
	ck_nonnull(decoder->event);
	ck_int_eq(decoder->event->type, ptev_enabled);
	ck_uint64_eq(decoder->event->variant.enabled.ip, dfix->last_ip.ip);
	ck_last_ip();

	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_ptr(ev, event);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_event_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event, *ev;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);

	errcode = pt_decode_tip_pge.decode(decoder);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, config->begin);
	ck_last_ip();

	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_ptr(ev, event);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_tip_pge_overflow)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_16bit;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_64bit;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	uint64_t at = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);
	ck_uint64_eq(event->variant.async_branch.from, dfix->last_ip.ip);

	check_non_ip_state(decoder);
}
END_TEST

START_TEST(check_decode_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_suppressed;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event *event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_fup(encoder, packet.ip, packet.ipc);

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_pip(encoder, cr3);

	event = pt_evq_enqueue(&decoder->evq, evb_tip);
	event->type = ptev_async_branch;

	errcode = pt_decode_pip.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_null(decoder->event);

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_branch);

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_async_paging);
	ck_uint64_eq(event->variant.async_paging.cr3, cr3);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_pip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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
static void check_clean_state(struct pt_query_decoder *decoder)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;

	ck_null(decoder->sync);

	pt_last_ip_init(&dfix->last_ip);
	ck_last_ip();

	pt_tnt_cache_init(&dfix->tnt);
	ck_tnt_cache();

	pt_time_init(&dfix->time);
	ck_time();
}

START_TEST(check_decode_ovf)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_fup);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_overflow);

	check_clean_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_disabled)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
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

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_overflow);

	check_clean_state(decoder);
}
END_TEST

START_TEST(check_decode_ovf_psbend_paging)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_bad_cr3;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_32bit;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_ovf(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_16bit;
	int errcode;

	check_encode_mode_exec(encoder, mode);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, mode);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_exec_fault)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);

	encoder->pos[-1] |= pt_mob_exec_csl | pt_mob_exec_csd;

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_evq_dequeue(&decoder->evq, evb_tip);
	ck_nonnull(event);
	ck_int_eq(event->type, ptev_exec_mode);
	ck_int_eq(event->variant.exec_mode.mode, ptem_unknown);

	check_blank_state(decoder);
}
END_TEST

START_TEST(check_decode_mode_tsx_xbegin)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_evq_dequeue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_evq_dequeue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event *event;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);

	errcode = pt_decode_mode.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);

	event = pt_evq_dequeue(&decoder->evq, evb_fup);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t cr3 = pt_dfix_bad_cr3;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	enum pt_exec_mode mode = ptem_32bit;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event *event;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_psbend(encoder);

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
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
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_time *time = &dfix->time;
	struct pt_packet_tsc packet;
	uint64_t flags = decoder->flags;
	int errcode;

	packet.tsc = 0x8c3a2ull;

	check_encode_tsc(encoder, packet.tsc);

	errcode = pt_time_update_tsc(time, &packet, config);
	ck_int_eq(errcode, 0);

	errcode = pt_decode_tsc.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_tsc_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_tsc(encoder, 0xffull);

	config->end = encoder->pos - 1;

	errcode = pt_decode_tsc.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_cbr)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_time *time = &dfix->time;
	struct pt_packet_cbr packet;
	uint64_t flags = decoder->flags;
	int errcode;

	packet.ratio = 0x42;

	check_encode_cbr(encoder, packet.ratio);

	errcode = pt_time_update_cbr(time, &packet, config);
	ck_int_eq(errcode, 0);

	errcode = pt_decode_cbr.decode(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->pos, encoder->pos);
	ck_uint64_eq(decoder->flags, flags);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

START_TEST(check_decode_cbr_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder = &dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t flags = decoder->flags;
	int errcode;

	check_encode_cbr(encoder, 0x23);

	config->end = encoder->pos - 1;

	errcode = pt_decode_cbr.decode(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, config->begin);
	ck_uint64_eq(decoder->flags, flags);
	ck_time();

	check_non_timing_state(decoder);
}
END_TEST

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

static struct tcase_desc tcase_header = {
	/* .name = */ "header",
	/* .add_tests = */ add_header_tests
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
	struct pt_query_decoder *decoder;

	pt_dfix_setup_standard();

	decoder = &dfix->decoder;
	pt_last_ip_init(&decoder->ip);
	pt_last_ip_init(&dfix->last_ip);
}

static void pt_dfix_setup_disabled(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_query_decoder *decoder;

	pt_dfix_setup_standard();

	decoder = &dfix->decoder;
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

	pt_add_tcase(suite, &tcase_header, &dfix_header);
	pt_add_tcase(suite, &tcase_decode, &dfix_standard);
	pt_add_tcase(suite, &tcase_disabled, &dfix_disabled);

	return suite;
}
