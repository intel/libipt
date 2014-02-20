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

#include "pt_decoder.h"

#include <check.h>


struct pt_decoder_fixture_s pt_decoder_fixture;

struct dfix_desc dfix_standard = {
	/* .name = */ "standard",
	/* .setup = */ pt_dfix_setup_standard
};

struct dfix_desc dfix_nosync = {
	/* .name = */ "nosync",
	/* .setup = */ pt_dfix_setup_nosync
};

static void init_fixture(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_config *config = &dfix->config;
	int errcode;

	(void) memset(dfix->buffer, 0, sizeof(dfix->buffer));

	errcode = pt_encoder_init(&pt_decoder_fixture.encoder, config);
	ck_int_eq(errcode, 0);

	pt_decoder_fixture.decoder = pt_alloc_decoder(config);
	ck_nonnull(pt_decoder_fixture.decoder);

	pt_decoder_fixture.decoder->ip.ip = pt_dfix_bad_ip;
	pt_decoder_fixture.decoder->ip.need_full_ip = 0;
	pt_decoder_fixture.decoder->ip.suppressed = 0;

	dfix->last_ip = pt_decoder_fixture.decoder->ip;
}

void pt_dfix_setup_config(struct pt_config *config)
{
	int errcode;

	errcode = pt_configure(config);
	ck_int_ge(errcode, 0);

	config->begin = pt_decoder_fixture.buffer;
	config->end = pt_decoder_fixture.buffer +
		sizeof(pt_decoder_fixture.buffer);
}

void pt_dfix_setup_nosync(void)
{
	pt_dfix_setup_config(&pt_decoder_fixture.config);
	init_fixture();
}

void pt_dfix_setup_standard(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;

	pt_dfix_setup_nosync();

	/* Synchronize the decoder at the beginning of the buffer. */
	dfix->decoder->pos = dfix->config.begin;
}

void pt_teardown_decoder_fixture(void)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;

	pt_free_decoder(dfix->decoder);
	dfix->decoder = NULL;
}

void pt_dfix_check_last_ip(const char *file, int line)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_last_ip *dip = &decoder->ip, *fip = &dfix->last_ip;

	ck_assert_msg(dip->ip == fip->ip, "Bad last-ip.ip. Got: 0x%" PRIx64
		      ", want: 0x%" PRIx64 " at %s:%d.",
		      dip->ip, fip->ip, file, line);
	ck_assert_msg(dip->need_full_ip == fip->need_full_ip,
		      "Bad last-ip.need_full_ip. Got: %u, want: %u at %s:%d.",
		      dip->need_full_ip, fip->need_full_ip, file, line);
	ck_assert_msg(dip->suppressed == fip->suppressed,
		      "Bad last-ip.suppressed. Got: %u, want: %u at %s:%d.",
		      dip->suppressed, fip->suppressed, file, line);
}

void pt_dfix_check_tnt_cache(const char *file, int line)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_tnt_cache *dtnt = &decoder->tnt, *ftnt = &dfix->tnt;

	ck_assert_msg(dtnt->tnt == ftnt->tnt,
		      "Bad tnt-cache.tnt. Got: 0x%" PRIx64 ", expected: 0x%"
		      PRIx64 " at %s:%d.", dtnt->tnt, ftnt->tnt, file, line);
	ck_assert_msg(dtnt->index == ftnt->index,
		      "Bad tnt-cache.index. Got: 0x%" PRIx64 ", expected: 0x%"
		      PRIx64 " at %s:%d.", dtnt->index, ftnt->index, file,
		      line);
}

static const char *create_tcase_name(const char *dd, const char *td)
{
	size_t namelen;
	char *name;
	int status;

	if (!td)
		return dd;

	namelen = strlen(td) + strlen(dd) + 3;
	name = malloc(namelen);
	if (!name)
		return dd;

	status = snprintf(name, namelen, "%s: %s", dd, td);
	if (status < 0) {
		free(name);
		return dd;
	}

	return name;
}

void pt_add_tcase(Suite *suite,
		   const struct tcase_desc *td,
		   const struct dfix_desc *dd)
{
	TCase *tcase;
	const char *name;

	name = create_tcase_name(dd->name, td->name);

	tcase = tcase_create(name);

	add_dfix(tcase, dd->setup);

	td->add_tests(tcase);

	suite_add_tcase(suite, tcase);
}

void *check_encode_pad(struct pt_encoder *encoder)
{
	int bytes;

	bytes = pt_encode_pad(encoder);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_psb(struct pt_encoder *encoder)
{
	int bytes;

	bytes = pt_encode_psb(encoder);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_psbend(struct pt_encoder *encoder)
{
	int bytes;

	bytes = pt_encode_psbend(encoder);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tip(struct pt_encoder *encoder, uint64_t ip,
		       enum pt_ip_compression ipc)
{
	int bytes;

	bytes = pt_encode_tip(encoder, ip, ipc);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tnt_8(struct pt_encoder *encoder, uint8_t tnt, int size)
{
	int bytes;

	bytes = pt_encode_tnt_8(encoder, tnt, size);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tnt_64(struct pt_encoder *encoder, uint64_t tnt, int size)
{
	int bytes;

	bytes = pt_encode_tnt_64(encoder, tnt, size);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tip_pge(struct pt_encoder *encoder, uint64_t ip,
			   enum pt_ip_compression ipc)
{
	int bytes;

	bytes = pt_encode_tip_pge(encoder, ip, ipc);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tip_pgd(struct pt_encoder *encoder, uint64_t ip,
			   enum pt_ip_compression ipc)
{
	int bytes;

	bytes = pt_encode_tip_pgd(encoder, ip, ipc);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_fup(struct pt_encoder *encoder, uint64_t ip,
		       enum pt_ip_compression ipc)
{
	int bytes;

	bytes = pt_encode_fup(encoder, ip, ipc);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_pip(struct pt_encoder *encoder, uint64_t cr3)
{
	int bytes;

	bytes = pt_encode_pip(encoder, cr3);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_ovf(struct pt_encoder *encoder)
{
	int bytes;

	bytes = pt_encode_ovf(encoder);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_mode_exec(struct pt_encoder *encoder,
			     enum pt_exec_mode mode)
{
	int bytes;

	bytes = pt_encode_mode_exec(encoder, mode);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_mode_tsx(struct pt_encoder *encoder, uint8_t flags)
{
	int bytes;

	bytes = pt_encode_mode_tsx(encoder, flags);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_tsc(struct pt_encoder *encoder, uint64_t tsc)
{
	int bytes;

	bytes = pt_encode_tsc(encoder, tsc);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}

void *check_encode_cbr(struct pt_encoder *encoder, uint8_t cbr)
{
	int bytes;

	bytes = pt_encode_cbr(encoder, cbr);
	ck_int_gt(bytes, 0);

	return encoder->pos;
}
