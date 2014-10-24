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
	ck_uint64_eq(decoder->time.tsc, 0);
	ck_uint64_eq(decoder->time.cbr, 0);

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
}

static struct tcase_desc tcase_initial = {
	/* .name = */ "initial",
	/* .add_tests = */ add_initial_tests
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

	return suite;
}
