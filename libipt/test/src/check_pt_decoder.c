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

#include "pt_decoder.h"

#include <check.h>


START_TEST(check_pt_initial)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;

	ck_null(decoder->pos);
	ck_null(decoder->next);
	ck_uint64_eq(decoder->flags, 0);
	ck_null(decoder->event);
	ck_uint64_eq(decoder->tsc, 0);

	pt_tnt_cache_init(&dfix->tnt);
	ck_tnt_cache();
}
END_TEST

START_TEST(check_pt_alloc_null)
{
	struct pt_decoder *decoder;

	decoder = pt_alloc_decoder(NULL);
	ck_null(decoder);
}
END_TEST

START_TEST(check_pt_alloc_bad_size)
{
	struct pt_decoder *decoder;
	struct pt_config config;

	pt_dfix_setup_config(&config);
	config.size = 0;

	decoder = pt_alloc_decoder(&config);
	ck_null(decoder);
}
END_TEST

START_TEST(check_pt_alloc_begin_null)
{
	struct pt_decoder *decoder;
	struct pt_config config;

	pt_dfix_setup_config(&config);
	config.begin = NULL;

	decoder = pt_alloc_decoder(&config);
	ck_null(decoder);
}
END_TEST

START_TEST(check_pt_alloc_end_null)
{
	struct pt_decoder *decoder;
	struct pt_config config;

	pt_dfix_setup_config(&config);
	config.end = NULL;

	decoder = pt_alloc_decoder(&config);
	ck_null(decoder);
}
END_TEST

START_TEST(check_pt_alloc_bad_buffer)
{
	struct pt_decoder *decoder;
	struct pt_config config;

	pt_dfix_setup_config(&config);
	config.begin = (uint8_t *) config.end + 1;

	decoder = pt_alloc_decoder(&config);
	ck_null(decoder);
}
END_TEST

START_TEST(check_pt_free_null)
{
	pt_free_decoder(NULL);
}
END_TEST

START_TEST(check_null_pos)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t offset;
	int errcode;

	errcode = pt_get_decoder_pos(NULL, NULL);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_get_decoder_pos(NULL, &offset);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_get_decoder_pos(decoder, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_initial_pos)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t offset;
	int errcode;

	errcode = pt_get_decoder_pos(decoder, &offset);
	ck_int_eq(errcode, -pte_nosync);
}
END_TEST

START_TEST(check_null_sync)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t offset;
	int errcode;

	errcode = pt_get_decoder_sync(NULL, NULL);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_get_decoder_sync(NULL, &offset);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_get_decoder_sync(decoder, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_initial_sync)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t offset;
	int errcode;

	errcode = pt_get_decoder_sync(decoder, &offset);
	ck_int_eq(errcode, -pte_nosync);
}
END_TEST

START_TEST(check_null_raw)
{
	const uint8_t *pos;

	pos = pt_get_decoder_raw(NULL);
	ck_null(pos);
}
END_TEST

START_TEST(check_initial_raw)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	const uint8_t *pos;

	pos = pt_get_decoder_raw(decoder);
	ck_null(pos);
}
END_TEST

START_TEST(check_raw)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &dfix->config;
	const uint8_t *pos, *exp;

	exp = &config->begin[42];
	decoder->pos = exp;

	pos = pt_get_decoder_raw(decoder);
	ck_ptr(pos, exp);
}
END_TEST

START_TEST(check_null_begin)
{
	const uint8_t *pos;

	pos = pt_get_decoder_begin(NULL);
	ck_null(pos);
}
END_TEST

START_TEST(check_initial_begin)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &dfix->config;
	const uint8_t *pos;

	pos = pt_get_decoder_begin(decoder);
	ck_ptr(pos, config->begin);
}
END_TEST

START_TEST(check_null_end)
{
	const uint8_t *pos;

	pos = pt_get_decoder_end(NULL);
	ck_null(pos);
}
END_TEST

START_TEST(check_initial_end)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &dfix->config;
	const uint8_t *pos;

	pos = pt_get_decoder_end(decoder);
	ck_ptr(pos, config->end);
}
END_TEST

START_TEST(check_null_event)
{
	struct pt_event *ev;
	int evb;

	for (evb = 0; evb < evb_max; ++evb) {
		ev = pt_enqueue_event(NULL, evb);
		ck_null(ev);

		ev = pt_dequeue_event(NULL, evb);
		ck_null(ev);

		pt_discard_events(NULL, evb);
	}
}
END_TEST

START_TEST(check_event_initially_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *ev;
	int evb, pend;

	for (evb = 0; evb < evb_max; ++evb) {
		pend = pt_event_pending(decoder, evb);
		ck_int_eq(pend, 0);

		ev = pt_dequeue_event(decoder, evb);
		ck_null(ev);
	}
}
END_TEST

START_TEST(check_event_enqueue_dequeue)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *ev[evb_max][2];
	int evb, pend;

	for (evb = 0; evb < evb_max; ++evb) {
		ev[evb][0] = pt_enqueue_event(decoder, evb);
		ck_nonnull(ev[evb][0]);

		pend = pt_event_pending(decoder, evb);
		ck_int_ne(pend, 0);

		ev[evb][1] = pt_enqueue_event(decoder, evb);
		ck_nonnull(ev[evb][1]);

		pend = pt_event_pending(decoder, evb);
		ck_int_ne(pend, 0);
	}

	for (evb = 0; evb < evb_max; ++evb) {
		struct pt_event *deq;

		deq = pt_dequeue_event(decoder, evb);
		ck_ptr(deq, ev[evb][0]);

		pend = pt_event_pending(decoder, evb);
		ck_int_ne(pend, 0);

		deq = pt_dequeue_event(decoder, evb);
		ck_ptr(deq, ev[evb][1]);

		pend = pt_event_pending(decoder, evb);
		ck_int_eq(pend, 0);

		deq = pt_dequeue_event(decoder, evb);
		ck_null(deq);
	}
}
END_TEST

START_TEST(check_event_discard)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *ev;
	int evb, pend;

	for (evb = 0; evb < evb_max; ++evb) {
		ev = pt_enqueue_event(decoder, evb);
		ck_nonnull(ev);

		pt_discard_events(decoder, evb);

		pend = pt_event_pending(decoder, evb);
		ck_int_eq(pend, 0);

		ev = pt_dequeue_event(decoder, evb);
		ck_null(ev);
	}
}
END_TEST

START_TEST(check_event_wrap)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *ev[2];
	int evb, it, pend;

	for (evb = 0; evb < evb_max; ++evb) {
		for (it = 0; it < evb_max_pend * 2; ++it) {
			ev[0] = pt_enqueue_event(decoder, evb);
			ck_nonnull(ev[0]);

			pend = pt_event_pending(decoder, evb);
			ck_int_ne(pend, 0);

			ev[1] = pt_dequeue_event(decoder, evb);
			ck_ptr(ev[1], ev[0]);

			pend = pt_event_pending(decoder, evb);
			ck_int_eq(pend, 0);

			ev[1] = pt_dequeue_event(decoder, evb);
			ck_null(ev[1]);
		}
	}
}
END_TEST

START_TEST(check_event_overflow)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *ev[evb_max][evb_max_pend - 2];
	int evb, it, pend;

	for (evb = 0; evb < evb_max; ++evb) {
		for (it = 0; it < evb_max_pend - 2; ++it) {
			ev[evb][it] = pt_enqueue_event(decoder, evb);
			ck_nonnull(ev[evb][it]);
		}
	}

	for (evb = 0; evb < evb_max; ++evb) {
		struct pt_event *ovf;

		pend = pt_event_pending(decoder, evb);
		ck_int_ne(pend, 0);

		ovf = pt_enqueue_event(decoder, evb);
		ck_null(ovf);

		pend = pt_event_pending(decoder, evb);
		ck_int_ne(pend, 0);
	}

	for (evb = 0; evb < evb_max; ++evb) {
		for (it = 0; it < evb_max_pend - 2; ++it) {
			struct pt_event *deq;

			pend = pt_event_pending(decoder, evb);
			ck_int_ne(pend, 0);

			deq = pt_dequeue_event(decoder, evb);
			ck_ptr(deq, ev[evb][it]);
		}
	}

	for (evb = 0; evb < evb_max; ++evb) {
		struct pt_event *deq;

		pend = pt_event_pending(decoder, evb);
		ck_int_eq(pend, 0);

		deq = pt_dequeue_event(decoder, evb);
		ck_null(deq);
	}
}
END_TEST

START_TEST(check_event_consistency)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event *event;
	int evb, errcode;

	for (evb = 0; evb < evb_max; ++evb) {
		decoder->ev_begin[evb] = evb_max_pend;
		decoder->ev_end[evb] = 0;

		event = pt_enqueue_event(decoder, evb);
		ck_null(event);

		event = pt_dequeue_event(decoder, evb);
		ck_null(event);

		errcode = pt_event_pending(decoder, evb);
		ck_int_eq(errcode, -pte_internal);

		decoder->ev_begin[evb] = 0;
		decoder->ev_end[evb] = evb_max_pend;

		event = pt_enqueue_event(decoder, evb);
		ck_null(event);

		event = pt_dequeue_event(decoder, evb);
		ck_null(event);

		errcode = pt_event_pending(decoder, evb);
		ck_int_eq(errcode, -pte_internal);
	}
}
END_TEST

static void add_alloc_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_pt_alloc_null);
	tcase_add_test(tcase, check_pt_alloc_bad_size);
	tcase_add_test(tcase, check_pt_alloc_begin_null);
	tcase_add_test(tcase, check_pt_alloc_end_null);
	tcase_add_test(tcase, check_pt_alloc_bad_buffer);
	tcase_add_test(tcase, check_pt_free_null);
}

static void add_initial_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_pt_initial);
	tcase_add_test(tcase, check_initial_pos);
	tcase_add_test(tcase, check_initial_sync);
	tcase_add_test(tcase, check_initial_raw);
	tcase_add_test(tcase, check_initial_begin);
	tcase_add_test(tcase, check_initial_end);
}

static void add_pos_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_null_pos);
	tcase_add_test(tcase, check_null_sync);
	tcase_add_test(tcase, check_null_raw);
	tcase_add_test(tcase, check_raw);
	tcase_add_test(tcase, check_null_begin);
	tcase_add_test(tcase, check_null_end);
}

static void add_event_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_null_event);
	tcase_add_test(tcase, check_event_initially_empty);
	tcase_add_test(tcase, check_event_enqueue_dequeue);
	tcase_add_test(tcase, check_event_discard);
	tcase_add_test(tcase, check_event_wrap);
	tcase_add_test(tcase, check_event_overflow);
	tcase_add_test(tcase, check_event_consistency);
}

static struct tcase_desc tcase_initial = {
	/* .name = */ "initial",
	/* .add_tests = */ add_initial_tests
};

static struct tcase_desc tcase_pos = {
	/* .name = */ "pos",
	/* .add_tests = */ add_pos_tests
};

static struct tcase_desc tcase_event = {
	/* .name = */ "event",
	/* .add_tests = */ add_event_tests
};

Suite *suite_pt_decoder(void)
{
	Suite *suite;
	TCase *alloc;

	alloc = tcase_create("decoder alloc");
	add_alloc_tests(alloc);

	suite = suite_create("pt decoder");
	suite_add_tcase(suite, alloc);

	pt_add_tcase(suite, &tcase_initial, &dfix_nosync);
	pt_add_tcase(suite, &tcase_pos, &dfix_standard);
	pt_add_tcase(suite, &tcase_event, &dfix_standard);

	return suite;
}
