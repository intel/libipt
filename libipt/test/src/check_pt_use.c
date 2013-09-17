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

#include "pt_decode.h"
#include "pt_error.h"

#include <check.h>


START_TEST(check_use_disable_discard_tail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_sext_ip;
	int errcode, taken;

	check_encode_tnt_8(encoder, 0, 4);
	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);
	check_encode_tip_pge(encoder, ip, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0xf, 4);

	pt_sync_decoder(decoder);

	/* The user queries the disable event. */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));
	ck_int_eq(event.type, ptev_disabled);

	/* He gives up trying to find the exact disable location and instead
	 * queries the next event.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, ip);

	/* The user jumps to the enable ip and starts decoding...until he
	 * arrives at a conditional branch.
	 *
	 * The query must use the TNT succeeding the TIP.PGE.
	 */
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, 0);
	ck_int_eq(taken, 1);
}
END_TEST

START_TEST(check_use_disable_search_tail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t ip = pt_dfix_max_ip;
	int errcode, taken;

	check_encode_tnt_8(encoder, 0, 1);
	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);
	check_encode_tip_pge(encoder, ip, pt_ipc_sext_48);
	check_encode_tnt_8(encoder, 0xf, 4);

	pt_sync_decoder(decoder);

	/* The user queries the disable event. */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));
	ck_int_eq(event.type, ptev_disabled);

	/* He searches for the exact disable location...and arrives at a
	 * conditional branch.
	 *
	 * The query must use the TNT preceding the TIP.PGD.
	 */
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(taken, 0);

	/* He searches further...and arrives at another conditional branch.
	 *
	 * The query must fail since no further TNT bits are cached.
	 */
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);

	/* He gives up and queries the next event.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, ip);

	/* The user jumps to the enable ip and starts decoding...until he
	 * arrives at a conditional branch.
	 *
	 * The query must use the TNT succeeding the TIP.PGE.
	 */
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, 0);
	ck_int_eq(taken, 1);
}
END_TEST

/* An asynchronous interrupt:
 *
 *   - switches execution mode
 *   - both interrupted program and handler are traced
 */
START_TEST(check_use_context_switch)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	enum pt_exec_mode mode[2];
	uint64_t ip[2], addr;
	int errcode, taken;

	mode[0] = ptem_32bit;
	mode[1] = ptem_64bit;

	ip[0] = pt_dfix_max_ip;
	ip[1] = pt_dfix_sext_ip;

	/* Interrupt. */
	check_encode_fup(encoder, ip[0], pt_ipc_sext_48);
	check_encode_mode_exec(encoder, mode[1]);
	check_encode_tip(encoder, ip[1], pt_ipc_sext_48);
	/* Return from interrupt. */
	check_encode_mode_exec(encoder, mode[0]);
	check_encode_tip(encoder, ip[0], pt_ipc_sext_48);

	pt_sync_decoder(decoder);

	/* Query the interrupt event.
	 *
	 * We proceed to the event location and jump to the branch destination.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_async_branch);
	ck_uint64_eq(event.variant.async_branch.from, ip[0]);
	ck_uint64_eq(event.variant.async_branch.to, ip[1]);

	/* The interrupt changes the execution mode.
	 *
	 * We're already at the event location, so we can immediately apply the
	 * execution mode change event.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode[1]);
	ck_uint64_eq(event.variant.exec_mode.ip, ip[1]);

	/* Query the pending event.
	 *
	 * This indicates the mode switch on return from the interrupt.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode[0]);
	ck_uint64_eq(event.variant.exec_mode.ip, ip[0]);

	/* While proceeding to the event ip, we come across the reti.
	 *
	 * We first try to query for a compressed return.
	 */
	errcode = pt_query_cond_branch(decoder, &taken);
	ck_int_eq(errcode, -pte_bad_query);

	/* We then query for the uncompressed return destination. */
	errcode = pt_query_uncond_branch(decoder, &addr);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(addr, ip[0]);

	/* We arrived at the execution mode event location and can now apply the
	 * execution mode change event.
	 */
}
END_TEST

/* An asynchronous interrupt:
 *
 *   - switches execution mode
 *   - the interrupted program is traced
 *   - the interrupt handler is cpl-filtered
 */
START_TEST(check_use_context_switch_cpl)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	enum pt_exec_mode mode[2];
	uint64_t ip = pt_dfix_max_ip;
	int errcode;

	mode[0] = ptem_32bit;
	mode[1] = ptem_64bit;

	/* Interrupt - disable tracing. */
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	/* We do not get a mode event, here. */
	check_encode_tip_pgd(encoder, 0, pt_ipc_suppressed);
	/* Return from interrupt - re-enable tracing. */
	check_encode_mode_exec(encoder, mode[0]);
	check_encode_tip_pge(encoder, ip, pt_ipc_update_16);

	pt_sync_decoder(decoder);

	/* Query the interrupt event.
	 *
	 * We proceed to the event location and note that tracing is disabled.
	 */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));
	ck_int_eq(event.type, ptev_async_disabled);
	ck_uint64_eq(event.variant.async_disabled.at, ip);

	/* Query the next event - waiting for the re-enable. */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, pts_event_pending);
	ck_int_eq(event.type, ptev_enabled);
	ck_uint64_eq(event.variant.enabled.ip, ip);

	/* We jump the the enable IP and query the pending event. */
	errcode = pt_query_event(decoder, &event);
	ck_int_eq(errcode, 0);
	ck_int_eq(event.type, ptev_exec_mode);
	ck_int_eq(event.variant.exec_mode.mode, mode[0]);
	ck_uint64_eq(event.variant.exec_mode.ip, ip);

	/* We are already at the execution mode event location and apply the
	 * execution mode change event immediately.
	 */
}
END_TEST

static void add_enable_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_use_disable_discard_tail);
	tcase_add_test(tcase, check_use_disable_search_tail);
}

static void add_context_switch_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_use_context_switch);
	tcase_add_test(tcase, check_use_context_switch_cpl);
}

static struct tcase_desc tcase_enable = {
	/* .name = */ "enable",
	/* .add_tests = */ add_enable_tests
};

static struct tcase_desc tcase_context_switch = {
	/* .name = */ "context switch",
	/* .add_tests = */ add_context_switch_tests
};

Suite *suite_pt_use(void)
{
	Suite *suite;

	suite = suite_create("pt use cases");

	pt_add_tcase(suite, &tcase_enable, &dfix_standard);
	pt_add_tcase(suite, &tcase_context_switch, &dfix_standard);

	return suite;
}
