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


START_TEST(check_sync_null)
{
	int errcode;

	errcode = pt_sync_forward(NULL);
	ck_int_eq(errcode, -pte_invalid);

	errcode = pt_sync_backward(NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_sync_empty)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	config->end = config->begin;

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_null(decoder->sync);
	ck_null(decoder->pos);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_null(decoder->sync);
	ck_null(decoder->pos);
}
END_TEST

START_TEST(check_sync_forward_direct)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_psb(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, config->begin);
	ck_ptr(decoder->pos, config->begin);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, config->begin);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

START_TEST(check_sync_backward_direct)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	check_encode_psb(encoder);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, config->begin);
	ck_ptr(decoder->pos, config->begin);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, config->begin);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

START_TEST(check_sync_forward)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	const void *pos[2];
	int errcode;

	check_encode_pad(encoder);
	pos[0] = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);
	check_encode_pad(encoder);
	pos[1] = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_pad(encoder);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos[0]);
	ck_ptr(decoder->pos, pos[0]);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos[1]);
	ck_ptr(decoder->pos, pos[1]);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, pos[1]);
	ck_ptr(decoder->pos, pos[1]);
}
END_TEST

START_TEST(check_sync_backward)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	const void *pos[2];
	int errcode;

	check_encode_pad(encoder);
	pos[0] = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_tip(encoder, 0, pt_ipc_suppressed);
	check_encode_pad(encoder);
	pos[1] = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_pad(encoder);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos[1]);
	ck_ptr(decoder->pos, pos[1]);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos[0]);
	ck_ptr(decoder->pos, pos[0]);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, pos[0]);
	ck_ptr(decoder->pos, pos[0]);
}
END_TEST

START_TEST(check_sync_forward_cutoff)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	const void *pos;
	int errcode;

	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_pad(encoder);
	pos = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_psb(encoder);

	config->begin += 1;
	config->end = encoder->pos - 1;

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos);
	ck_ptr(decoder->pos, pos);

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, pos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_sync_backward_cutoff)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_config *config = &decoder->config;
	const void *pos;
	int errcode;

	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_pad(encoder);
	pos = check_encode_pad(encoder);
	check_encode_psb(encoder);
	check_encode_psbend(encoder);
	check_encode_psb(encoder);

	config->begin += 1;
	config->end = encoder->pos - 1;

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, 0);
	ck_ptr(decoder->sync, pos);
	ck_ptr(decoder->pos, pos);

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_ptr(decoder->sync, pos);
	ck_ptr(decoder->pos, pos);
}
END_TEST

START_TEST(check_sync_forward_end)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	decoder->pos = config->end;

	errcode = pt_sync_forward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_null(decoder->sync);
	ck_ptr(decoder->pos, config->end);
}
END_TEST

START_TEST(check_sync_backward_begin)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode;

	decoder->pos = config->begin;

	errcode = pt_sync_backward(decoder);
	ck_int_eq(errcode, -pte_eos);
	ck_null(decoder->sync);
	ck_ptr(decoder->pos, config->begin);
}
END_TEST

static void add_sync_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_sync_null);
	tcase_add_test(tcase, check_sync_empty);
	tcase_add_test(tcase, check_sync_forward_direct);
	tcase_add_test(tcase, check_sync_backward_direct);
	tcase_add_test(tcase, check_sync_forward);
	tcase_add_test(tcase, check_sync_backward);
	tcase_add_test(tcase, check_sync_forward_cutoff);
	tcase_add_test(tcase, check_sync_backward_cutoff);
	tcase_add_test(tcase, check_sync_forward_end);
	tcase_add_test(tcase, check_sync_backward_begin);
}

static struct tcase_desc tcase_sync = {
	/* .name = */ "sync",
	/* .add_tests = */ add_sync_tests
};

Suite *suite_pt_sync(void)
{
	Suite *suite;

	suite = suite_create("pt decoder sync");
	pt_add_tcase(suite, &tcase_sync, &dfix_nosync);

	return suite;
}
