/*
 * Copyright (c) 2013, Intel Corporation
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

#include "pt_query.h"
#include "pt_packet.h"
#include "pt_error.h"

#include <check.h>


START_TEST(check_query_start_nosync_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_nosync);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_start_off_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	decoder->sync = config->begin;
	decoder->pos = config->begin + 1;

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_nosync);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_not_synced)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_nosync);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_cond_not_synced)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	int errcode, tnt = 0xbc, taken = tnt;

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_nosync);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_event_not_synced)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event event;
	int errcode;

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_nosync);
}
END_TEST

START_TEST(check_query_uncond_null)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_uncond_branch(NULL, &addr);
	ck_int_eq(errcode, -pte_invalid);
	ck_uint64_eq(addr, ip);

	errcode = pt_query_uncond_branch(decoder, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

START_TEST(check_query_uncond_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	decoder->pos = config->end;

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_eos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_uncond_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_uncond_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_uncond_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_eos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_skip_tnt_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	check_encode_tnt_8(encoder, 0, 1);
	check_encode_tnt_8(encoder, 0, 1);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_bad_query);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_skip_tip_pge_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_tip_pge(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_skip_tip_pgd_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_skip_fup_tip_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = check_encode_fup(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_uncond_skip_fup_tip_pgd_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = check_encode_fup(encoder, 0, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_cond_null)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode, tnt = 0xbc, taken = tnt;

	errcode = pt_query_cond_branch(NULL, &taken);
	ck_int_eq(errcode, -pte_invalid);
	ck_int_eq(taken, tnt);

	errcode = pt_query_cond_branch(decoder, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

START_TEST(check_query_cond_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode, tnt = 0xbc, taken = tnt;

	decoder->pos = config->end;

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_eos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;

	check_encode_tnt_8(encoder, 0x02, 3);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, 0);
	ck_int_eq(taken, 0);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, 0);
	ck_int_eq(taken, 1);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, 0);
	ck_int_eq(taken, 0);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_eos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond_skip_tip_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	check_encode_tip(encoder, 0, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond_skip_tip_pge_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	check_encode_tip_pge(encoder, 0, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond_skip_tip_pgd_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond_skip_fup_tip_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = check_encode_fup(encoder, 0, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_cond_skip_fup_tip_pgd_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = check_encode_fup(encoder, 0, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
	ck_int_eq(taken, tnt);
}
END_TEST

START_TEST(check_query_event_null)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	errcode = pt_query_event(NULL, &event);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_query_event(decoder, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

START_TEST(check_query_event_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	decoder->pos = config->end;

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_enabled_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_tip_pge(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
}
END_TEST

START_TEST(check_query_event_enabled_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_enabled_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_enabled_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_enabled_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_tip_pge(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_disabled_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_disabled);
}
END_TEST

START_TEST(check_query_event_disabled_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_disabled);
	ck_uint64_eq(event.variant.disabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_disabled_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_disabled);
	ck_uint64_eq(event.variant.disabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_disabled_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_disabled);
	ck_uint64_eq(event.variant.disabled.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_disabled_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_tip_pgd(encoder, 0, pt_ipc_update_32);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_async_disabled_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t at = pt_dfix_sext_ip;
	int errcode;

	check_encode_fup(encoder, at, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_async_disabled);
	ck_uint64_eq(event.variant.async_disabled.at, at);
}
END_TEST

START_TEST(check_query_event_async_disabled_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_fup(encoder, 0, pt_ipc_suppressed);
	check_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
}
END_TEST

START_TEST(check_query_event_async_disabled_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, at = ip & ~0xffffull;
	int errcode;

	check_encode_fup(encoder, at, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0xffffull, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_disabled);
	ck_uint64_eq(event.variant.async_disabled.at, at);
	ck_uint64_eq(event.variant.async_disabled.ip, ip);
}
END_TEST

START_TEST(check_query_event_async_disabled_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, at = ip & ~0xffffffffull;
	int errcode;

	check_encode_fup(encoder, at, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0xffffffffull, pt_ipc_update_32);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_disabled);
	ck_uint64_eq(event.variant.async_disabled.at, at);
	ck_uint64_eq(event.variant.async_disabled.ip, ip);
}
END_TEST

START_TEST(check_query_event_async_disabled_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, at = ip & ~0xf00full;
	int errcode;

	check_encode_fup(encoder, at, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, ip, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_disabled);
	ck_uint64_eq(event.variant.async_disabled.at, at);
	ck_uint64_eq(event.variant.async_disabled.ip, ip);
}
END_TEST

START_TEST(check_query_event_async_disabled_cutoff_fail_a)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	uint64_t at = pt_dfix_sext_ip;
	const uint8_t *pos;
	int errcode;

	pos = check_encode_fup(encoder, at, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_async_disabled_cutoff_fail_b)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_fup(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_async_branch_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t from = pt_dfix_max_ip;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);
}
END_TEST

START_TEST(check_query_event_async_branch_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_fup(encoder, 0, pt_ipc_suppressed);
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_async_branch_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t to = pt_dfix_max_ip, from = to & ~0xffffull;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_tip(encoder, 0xffffull, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);
	ck_uint64_eq(event.variant.async_branch.to, to);
}
END_TEST

START_TEST(check_query_event_async_branch_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t to = pt_dfix_max_ip, from = to & ~0xffffffffull;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_tip(encoder, 0xffffffffull, pt_ipc_update_32);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);
	ck_uint64_eq(event.variant.async_branch.to, to);
}
END_TEST

START_TEST(check_query_event_async_branch_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t from = pt_dfix_max_ip, to = pt_dfix_sext_ip;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_tip(encoder, to, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);
	ck_uint64_eq(event.variant.async_branch.to, to);
}
END_TEST

START_TEST(check_query_event_async_branch_cutoff_fail_a)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = check_encode_fup(encoder, 0, pt_ipc_sext_48);
	check_encode_tip_pgd(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_async_branch_cutoff_fail_b)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_fup(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_paging)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_pip(encoder, cr3);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_paging);
	ck_uint64_eq(event.variant.paging.cr3, cr3);
}
END_TEST

START_TEST(check_query_event_async_paging)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t to = pt_dfix_sext_ip, from = to & ~0xffffull;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_pip(encoder, cr3);
	check_encode_tip(encoder, to, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);
	ck_uint64_eq(event.variant.async_branch.to, to);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_paging);
	ck_uint64_eq(event.variant.async_paging.cr3, cr3);
	ck_uint64_eq(event.variant.async_paging.ip, to);
}
END_TEST

START_TEST(check_query_event_async_paging_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t from = pt_dfix_sext_ip, cr3 = pt_dfix_max_cr3;
	int errcode;

	check_encode_fup(encoder, from, pt_ipc_sext_48);
	check_encode_pip(encoder, cr3);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, from);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_async_paging);
	ck_uint64_eq(event.variant.async_paging.cr3, cr3);
}
END_TEST

START_TEST(check_query_event_paging_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_pip(encoder, 0);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_overflow_fup_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
}
END_TEST

START_TEST(check_query_event_overflow_fup_update_16_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_query_event_overflow_fup_update_32_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_32);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_query_event_overflow_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_sext_ip;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_overflow);
	ck_uint64_eq(event.variant.overflow.ip, ip);
}
END_TEST

START_TEST(check_query_event_overflow_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_overflow_tip_pge_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_tip_pge(encoder, 0, pt_ipc_suppressed);

	decoder->flags |= pdf_pt_disabled;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
}
END_TEST

START_TEST(check_query_event_overflow_tip_pge_update_16_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_tip_pge(encoder, 0, pt_ipc_update_16);

	decoder->flags |= pdf_pt_disabled;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_query_event_overflow_tip_pge_update_32_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_tip_pge(encoder, 0, pt_ipc_update_32);

	decoder->flags |= pdf_pt_disabled;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_query_event_overflow_tip_pge_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_sext_ip;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_tip_pge(encoder, ip, pt_ipc_sext_48);

	decoder->flags |= pdf_pt_disabled;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_overflow);
	ck_uint64_eq(event.variant.overflow.ip, ip);
}
END_TEST

START_TEST(check_query_event_overflow_tip_pge_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);
	check_encode_tip_pge(encoder, 0, pt_ipc_update_32);

	decoder->flags |= pdf_pt_disabled;
	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_overflow_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_ovf(encoder);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_64bit;
	struct pt_event event;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	check_encode_mode_exec(encoder, mode);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdcdcdull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_32bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_mode_exec(encoder, ptem_32bit);
	check_encode_tip(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_pge_suppressed_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	check_encode_mode_exec(encoder, ptem_32bit);
	check_encode_tip_pge(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_uint64_eq(addr, ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_pge_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_64bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_pge_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_64bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcdcdccddull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip_pge(encoder, packet.ip, packet.ipc);


	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_pge_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xcddcull;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	check_encode_mode_exec(encoder, mode);
	check_encode_tip_pge(encoder, packet.ip, packet.ipc);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, dfix->last_ip.ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
	ck_uint64_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);
}
END_TEST

START_TEST(check_query_event_exec_mode_tip_pge_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_mode_exec(encoder, ptem_16bit);
	check_encode_tip_pge(encoder, 0, pt_ipc_sext_48);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_exec_mode_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_mode_exec(encoder, ptem_64bit);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_tsx_fup_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);
	check_encode_fup(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_ip_suppressed);
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 1);
	ck_int_eq(event.variant.tsx.aborted, 0);
}
END_TEST

START_TEST(check_query_event_tsx_fup_update_16)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, br = ip & ~0xffffull;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 1);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, ip);
	ck_uint64_eq(event.variant.async_branch.to, br);
}
END_TEST

START_TEST(check_query_event_tsx_fup_update_32)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, br = ip & ~0xffffffffull;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_abrt);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_tip(encoder, 0, pt_ipc_update_32);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 1);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, ip);
	ck_uint64_eq(event.variant.async_branch.to, br);
}
END_TEST

START_TEST(check_query_event_tsx_fup_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, br = pt_dfix_sext_ip, addr = 0;
	int errcode;

	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_tip(encoder, br, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 1);
	ck_int_eq(event.variant.tsx.aborted, 0);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, br);
}
END_TEST

START_TEST(check_query_event_tsx_fup_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_mode_tsx(encoder, 0);
	check_encode_fup(encoder, 0, pt_ipc_update_16);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_tsx_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	check_encode_mode_tsx(encoder, 0);

	config->end = encoder->pos - 1;

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_event_skip_tip_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	check_encode_tip(encoder, 0, pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_query);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_query_event_skip_tnt_8_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_tnt_8(encoder, 0, 1);
	check_encode_tnt_8(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_query);
}
END_TEST

START_TEST(check_query_event_skip_tnt_64_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	check_encode_tnt_64(encoder, 0, 1);
	check_encode_tnt_64(encoder, 0, 1);

	pt_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_bad_query);
}
END_TEST

START_TEST(check_sync_query_event_suppressed_a)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_32bit;
	struct pt_event event;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_mode_tsx(encoder, 0);
	check_encode_mode_exec(encoder, mode);
	check_encode_psbend(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed |
			    pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_ip_suppressed | pts_status_event));
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
}
END_TEST

START_TEST(check_sync_query_event_suppressed_b)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_32bit;
	struct pt_event event;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_mode_tsx(encoder, 0);
	check_encode_mode_exec(encoder, mode);
	check_encode_fup(encoder, 0, pt_ipc_suppressed);
	check_encode_psbend(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed |
				pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_ip_suppressed | pts_status_event));
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);
}
END_TEST

START_TEST(check_sync_query_event_update_16_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_16);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_sync_query_event_update_32_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_32);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_sync_query_event_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, addr = 0;
	int errcode;

	check_encode_psb(encoder);
	check_encode_mode_tsx(encoder, 0);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_psbend(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, pts_event_pending);
	ck_uint64_eq(addr, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_status_event);
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);
	ck_uint64_eq(event.variant.tsx.ip, ip);
}
END_TEST

START_TEST(check_sync_query_event_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_psbend(encoder);

	config->end = encoder->pos - 1;

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_sync_query_event_incomplete_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_sync_overflow_query_event_suppressed)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	enum pt_exec_mode mode = ptem_32bit;
	uint64_t ov = pt_dfix_sext_ip, addr = 0;
	int errcode;

	check_encode_psb(encoder);
	check_encode_mode_exec(encoder, mode);
	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);
	check_encode_ovf(encoder);
	check_encode_fup(encoder, ov, pt_ipc_sext_48);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed |
				pts_status_event));
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed |
				pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 1);
	ck_int_eq(event.variant.tsx.aborted, 0);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_overflow);
	ck_uint64_eq(event.variant.overflow.ip, ov);
}
END_TEST

START_TEST(check_sync_overflow_query_event_update_16_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, addr = 0;
	int errcode;

	check_encode_psb(encoder);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_mode_tsx(encoder, 0);
	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_16);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, pts_event_pending);
	ck_uint64_eq(addr, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_sync_overflow_query_event_update_32_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, addr = 0;
	int errcode;

	check_encode_psb(encoder);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_mode_tsx(encoder, 0);
	check_encode_ovf(encoder);
	check_encode_fup(encoder, 0, pt_ipc_update_32);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, pts_event_pending);
	ck_uint64_eq(addr, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_sync_overflow_query_event_sext_48)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip, ov = pt_dfix_sext_ip, addr = 0;
	int errcode;

	check_encode_psb(encoder);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_mode_tsx(encoder, 0);
	check_encode_ovf(encoder);
	check_encode_fup(encoder, ov, pt_ipc_sext_48);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, pts_event_pending);
	ck_uint64_eq(addr, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_status_event));
	ck_int_eq(event.type, ptev_tsx);
	ck_int_eq(event.variant.tsx.speculative, 0);
	ck_int_eq(event.variant.tsx.aborted, 0);
	ck_uint64_eq(event.variant.tsx.ip, ip);

	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_overflow);
	ck_uint64_eq(event.variant.overflow.ip, ov);
}
END_TEST

START_TEST(check_sync_overflow_query_event_cutoff_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	uint64_t addr;
	int errcode;

	check_encode_psb(encoder);
	check_encode_ovf(encoder);

	config->end = encoder->pos - 1;

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ck_int_eq(errcode, -pte_eos);
}
END_TEST

START_TEST(check_query_tsc_null_fail)
{
	uint64_t tsc;

	tsc = pt_query_time(NULL);
	ck_uint64_eq(tsc, 0);
}
END_TEST

START_TEST(check_query_tsc_initial_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t tsc;

	tsc = pt_query_time(decoder);
	ck_uint64_eq(tsc, 0);
}
END_TEST

START_TEST(check_query_tsc)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t tsc, exp;

	exp = 0x11223344556677ull;

	check_encode_tsc(encoder, exp);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);

	pt_sync_decoder(decoder);
	pt_read_ahead(decoder);

	tsc = pt_query_time(decoder);
	ck_uint64_eq(tsc, exp);
}
END_TEST

static void add_nosync_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_start_nosync_fail);
	tcase_add_test(tcase, check_query_uncond_not_synced);
	tcase_add_test(tcase, check_query_cond_not_synced);
	tcase_add_test(tcase, check_query_event_not_synced);
}

static void add_neg_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_start_off_fail);
	tcase_add_test(tcase, check_query_uncond_null);
	tcase_add_test(tcase, check_query_uncond_empty);
	tcase_add_test(tcase, check_query_cond_null);
	tcase_add_test(tcase, check_query_cond_empty);
	tcase_add_test(tcase, check_query_event_null);
	tcase_add_test(tcase, check_query_event_empty);
}

static void add_uncond_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_uncond_suppressed);
	tcase_add_test(tcase, check_query_uncond_sext_48);
	tcase_add_test(tcase, check_query_uncond_cutoff_fail);
	tcase_add_test(tcase, check_query_uncond_skip_tnt_fail);
	tcase_add_test(tcase, check_query_uncond_skip_tip_pge_fail);
	tcase_add_test(tcase, check_query_uncond_skip_tip_pgd_fail);
	tcase_add_test(tcase, check_query_uncond_skip_fup_tip_fail);
	tcase_add_test(tcase, check_query_uncond_skip_fup_tip_pgd_fail);
}

/* Update tests can't skip PSB since this resets IP. */
static void add_uncond_nopsb_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_uncond_update_16);
	tcase_add_test(tcase, check_query_uncond_update_32);
}

static void add_cond_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_cond);
	tcase_add_test(tcase, check_query_cond_skip_tip_fail);
	tcase_add_test(tcase, check_query_cond_skip_tip_pge_fail);
	tcase_add_test(tcase, check_query_cond_skip_tip_pgd_fail);
	tcase_add_test(tcase, check_query_cond_skip_fup_tip_fail);
	tcase_add_test(tcase, check_query_cond_skip_fup_tip_pgd_fail);
}

static void add_event_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_event_enabled_suppressed_fail);
	tcase_add_test(tcase, check_query_event_enabled_sext_48);
	tcase_add_test(tcase, check_query_event_enabled_cutoff_fail);

	tcase_add_test(tcase, check_query_event_disabled_suppressed);
	tcase_add_test(tcase, check_query_event_disabled_sext_48);
	tcase_add_test(tcase, check_query_event_disabled_cutoff_fail);

	tcase_add_test(tcase, check_query_event_async_disabled_suppressed);
	tcase_add_test(tcase, check_query_event_async_disabled_suppressed_fail);
	tcase_add_test(tcase, check_query_event_async_disabled_update_16);
	tcase_add_test(tcase, check_query_event_async_disabled_update_32);
	tcase_add_test(tcase, check_query_event_async_disabled_sext_48);
	tcase_add_test(tcase, check_query_event_async_disabled_cutoff_fail_a);
	tcase_add_test(tcase, check_query_event_async_disabled_cutoff_fail_b);

	tcase_add_test(tcase, check_query_event_async_branch_suppressed);
	tcase_add_test(tcase, check_query_event_async_branch_suppressed_fail);
	tcase_add_test(tcase, check_query_event_async_branch_update_16);
	tcase_add_test(tcase, check_query_event_async_branch_update_32);
	tcase_add_test(tcase, check_query_event_async_branch_sext_48);
	tcase_add_test(tcase, check_query_event_async_branch_cutoff_fail_a);
	tcase_add_test(tcase, check_query_event_async_branch_cutoff_fail_b);

	tcase_add_test(tcase, check_query_event_paging);
	tcase_add_test(tcase, check_query_event_async_paging);
	tcase_add_test(tcase, check_query_event_async_paging_suppressed);
	tcase_add_test(tcase, check_query_event_paging_cutoff_fail);

	tcase_add_test(tcase, check_query_event_overflow_cutoff_fail);

	tcase_add_test(tcase, check_query_event_exec_mode_tip_suppressed);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_sext_48);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_cutoff_fail);

	tcase_add_test(tcase,
		       check_query_event_exec_mode_tip_pge_suppressed_fail);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_pge_sext_48);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_pge_cutoff_fail);
	tcase_add_test(tcase, check_query_event_exec_mode_cutoff_fail);

	tcase_add_test(tcase, check_query_event_tsx_fup_suppressed);
	tcase_add_test(tcase, check_query_event_tsx_fup_sext_48);
	tcase_add_test(tcase, check_query_event_tsx_fup_cutoff_fail);
	tcase_add_test(tcase, check_query_event_tsx_cutoff_fail);

	tcase_add_test(tcase, check_query_event_skip_tip_fail);
	tcase_add_test(tcase, check_query_event_skip_tnt_8_fail);
	tcase_add_test(tcase, check_query_event_skip_tnt_64_fail);
}

/* Some tests do not work if we skip PSB for various reasons. */
static void add_event_nopsb_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_event_enabled_update_16);
	tcase_add_test(tcase, check_query_event_enabled_update_32);

	tcase_add_test(tcase, check_query_event_disabled_update_16);
	tcase_add_test(tcase, check_query_event_disabled_update_32);

	tcase_add_test(tcase, check_query_event_overflow_fup_suppressed_fail);
	tcase_add_test(tcase, check_query_event_overflow_fup_update_16_fail);
	tcase_add_test(tcase, check_query_event_overflow_fup_update_32_fail);
	tcase_add_test(tcase, check_query_event_overflow_fup_sext_48);
	tcase_add_test(tcase, check_query_event_overflow_fup_cutoff_fail);

	tcase_add_test(tcase, check_query_event_exec_mode_tip_update_16);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_update_32);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_pge_update_16);
	tcase_add_test(tcase, check_query_event_exec_mode_tip_pge_update_32);

	tcase_add_test(tcase,
		       check_query_event_overflow_tip_pge_suppressed_fail);
	tcase_add_test(tcase,
		       check_query_event_overflow_tip_pge_update_16_fail);
	tcase_add_test(tcase,
		       check_query_event_overflow_tip_pge_update_32_fail);
	tcase_add_test(tcase, check_query_event_overflow_tip_pge_sext_48);
	tcase_add_test(tcase, check_query_event_overflow_tip_pge_cutoff_fail);

	tcase_add_test(tcase, check_query_event_tsx_fup_update_16);
	tcase_add_test(tcase, check_query_event_tsx_fup_update_32);

	tcase_add_test(tcase, check_sync_query_event_suppressed_a);
	tcase_add_test(tcase, check_sync_query_event_suppressed_b);
	tcase_add_test(tcase, check_sync_query_event_update_16_fail);
	tcase_add_test(tcase, check_sync_query_event_update_32_fail);
	tcase_add_test(tcase, check_sync_query_event_sext_48);
	tcase_add_test(tcase, check_sync_query_event_cutoff_fail);
	tcase_add_test(tcase, check_sync_query_event_incomplete_fail);

	tcase_add_test(tcase, check_sync_overflow_query_event_suppressed);
	tcase_add_test(tcase, check_sync_overflow_query_event_update_32_fail);
	tcase_add_test(tcase, check_sync_overflow_query_event_update_16_fail);
	tcase_add_test(tcase, check_sync_overflow_query_event_sext_48);
	tcase_add_test(tcase, check_sync_overflow_query_event_cutoff_fail);
}

static void add_timing_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_query_tsc_null_fail);
	tcase_add_test(tcase, check_query_tsc_initial_fail);
	tcase_add_test(tcase, check_query_tsc);
}

static struct tcase_desc tcase_nosync = {
	/* .name = */ "query nosync",
	/* .add_tests = */ add_nosync_tests
};

static struct tcase_desc tcase_neg = {
	/* .name = */ "query neg",
	/* .add_tests = */ add_neg_tests
};

static struct tcase_desc tcase_uncond = {
	/* .name = */ "query uncond",
	/* .add_tests = */ add_uncond_tests
};

static struct tcase_desc tcase_uncond_nopsb = {
	/* .name = */ "query uncond nopsb",
	/* .add_tests = */ add_uncond_nopsb_tests
};

static struct tcase_desc tcase_cond = {
	/* .name = */ "query cond",
	/* .add_tests = */ add_cond_tests
};

static struct tcase_desc tcase_event = {
	/* .name = */ "query event",
	/* .add_tests = */ add_event_tests
};

static struct tcase_desc tcase_event_nopsb = {
	/* .name = */ "query event nopsb",
	/* .add_tests = */ add_event_nopsb_tests
};

static struct tcase_desc tcase_timing = {
	/* .name = */ "query timing",
	/* .add_tests = */ add_timing_tests
};

static void pt_dfix_setup_skip_pad(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_dfix_setup_standard();

	check_encode_pad(encoder);
}

static void pt_dfix_setup_skip_psb(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_dfix_setup_standard();

	/* The psb must be empty since the tests won't skip status events.
	   On the other hand, we do need to provide an address since tests
	   may want to update last-ip, which requires a last-ip, of course.  */
	check_encode_psb(encoder);
	check_encode_fup(encoder, pt_dfix_sext_ip, pt_ipc_sext_48);
	check_encode_psbend(encoder);
}

static void pt_dfix_setup_skip_tnt_8(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_dfix_setup_standard();

	check_encode_tnt_8(encoder, 0, 4);
}

static void pt_dfix_setup_skip_tnt_64(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_dfix_setup_standard();

	check_encode_tnt_64(encoder, 0, 27);
}

static struct dfix_desc dfix_skip_pad = {
	/* .name = */ "skip pad",
	/* .setup = */ pt_dfix_setup_skip_pad
};

static struct dfix_desc dfix_skip_psb = {
	/* .name = */ "skip psb",
	/* .setup = */ pt_dfix_setup_skip_psb
};

static struct dfix_desc dfix_skip_tnt_8 = {
	/* .name = */ "skip tnt_8",
	/* .setup = */ pt_dfix_setup_skip_tnt_8
};

static struct dfix_desc dfix_skip_tnt_64 = {
	/* .name = */ "skip tnt_64",
	/* .setup = */ pt_dfix_setup_skip_tnt_64
};

static const struct dfix_desc *dfix_skip_all[] = {
	&dfix_standard,
	&dfix_skip_pad,
	&dfix_skip_psb,
	&dfix_skip_tnt_8,
	&dfix_skip_tnt_64,
	NULL
};

static const struct dfix_desc *dfix_skip_notnt[] = {
	&dfix_standard,
	&dfix_skip_pad,
	&dfix_skip_psb,
	NULL
};

static const struct dfix_desc *dfix_skip_nopsb[] = {
	&dfix_standard,
	&dfix_skip_pad,
	&dfix_skip_tnt_8,
	&dfix_skip_tnt_64,
	NULL
};

Suite *suite_pt_query(void)
{
	Suite *suite;

	suite = suite_create("pt query");

	pt_add_tcase(suite, &tcase_nosync, &dfix_nosync);
	pt_add_tcase(suite, &tcase_neg, &dfix_standard);
	pt_add_tcase_series(suite, &tcase_uncond, dfix_skip_all);
	pt_add_tcase_series(suite, &tcase_uncond_nopsb, dfix_skip_nopsb);
	pt_add_tcase_series(suite, &tcase_cond, dfix_skip_notnt);
	pt_add_tcase_series(suite, &tcase_event, dfix_skip_all);
	pt_add_tcase_series(suite, &tcase_event_nopsb, dfix_skip_nopsb);
	pt_add_tcase(suite, &tcase_timing, &dfix_standard);

	return suite;
}
