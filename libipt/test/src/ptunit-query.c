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

#include "ptunit.h"

#include "pt_last_ip.h"
#include "pt_packet_decode.h"
#include "pt_decoder.h"
#include "pt_encoder.h"


/* A query testing fixture. */

struct ptu_decoder_fixture {
	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct ptu_decoder_fixture *);
	struct ptunit_result (*fini)(struct ptu_decoder_fixture *);

	/* Encode an optional header for the test to read over. */
	struct ptunit_result (*header)(struct ptu_decoder_fixture *);

	/* The trace buffer. */
	uint8_t buffer[1024];

	/* The configuration under test. */
	struct pt_config config;

	/* A encoder and decoder for the above configuration. */
	struct pt_encoder encoder;
	struct pt_decoder *decoder;

	/* For tracking last-ip in tests. */
	struct pt_last_ip last_ip;
};

/* An invalid address. */
static const uint64_t pt_dfix_bad_ip = (1ull << 62) - 1;

/* A sign-extended address. */
static const uint64_t pt_dfix_sext_ip = 0xffffff00ff00ff00ull;

/* The highest possible address. */
static const uint64_t pt_dfix_max_ip = (1ull << 47) - 1;

/* The highest possible cr3 value. */
static const uint64_t pt_dfix_max_cr3 = ((1ull << 47) - 1) & ~0x1f;

/* Synchronize the decoder at the beginning of the trace stream, avoiding the
 * initial PSB header.
 */
static inline void ptu_sync_decoder(struct pt_decoder *decoder)
{
	(void) pt_fetch_decoder(decoder);
}

/* Cut off the last encoded packet. */
static struct ptunit_result cutoff(struct pt_decoder *decoder,
				   const struct pt_encoder *encoder)
{
	uint8_t *pos;

	ptu_ptr(decoder);
	ptu_ptr(encoder);

	pos = encoder->pos;
	ptu_ptr(pos);

	pos -= 1;
	ptu_ptr_le(decoder->config.begin, pos);

	decoder->config.end = pos;
	return ptu_passed();
}

static struct ptunit_result start_nosync_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, -pte_nosync);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result start_off_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	decoder->sync = config->begin;
	decoder->pos = config->begin + 1;

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, -pte_nosync);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result uncond_not_synced(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_nosync);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result cond_not_synced(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	int errcode, tnt = 0xbc, taken = tnt;

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_nosync);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result event_not_synced(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_event event;
	int errcode;

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_nosync);

	return ptu_passed();
}

static struct ptunit_result uncond_null(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	errcode = pt_query_uncond_branch(NULL, &addr);
	ptu_int_eq(errcode, -pte_invalid);
	ptu_uint_eq(addr, ip);

	errcode = pt_query_uncond_branch(decoder, NULL);
	ptu_int_eq(errcode, -pte_invalid);
	ptu_ptr_eq(decoder->pos, config->begin);

	return ptu_passed();
}

static struct ptunit_result uncond_empty(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	decoder->pos = config->end;

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_eos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result uncond(struct ptu_decoder_fixture *dfix,
				   enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	uint64_t addr = pt_dfix_bad_ip;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_tip(encoder, packet.ip, packet.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	if (ipc == pt_ipc_suppressed) {
		ptu_int_eq(errcode, pts_ip_suppressed);
		ptu_uint_eq(addr, pt_dfix_bad_ip);
	} else {
		ptu_int_eq(errcode, 0);
		ptu_uint_eq(addr, dfix->last_ip.ip);
	}

	return ptu_passed();
}

static struct ptunit_result uncond_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_eos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result
uncond_skip_tnt_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	int errcode;

	pt_encode_tnt_8(encoder, 0, 1);
	pt_encode_tnt_8(encoder, 0, 1);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result
uncond_skip_tip_pge_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_tip_pge(encoder, 0, pt_ipc_sext_48);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result
uncond_skip_tip_pgd_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result
uncond_skip_fup_tip_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result
uncond_skip_fup_tip_pgd_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t ip = pt_dfix_bad_ip, addr = ip;
	const uint8_t *pos;
	int errcode;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_uint_eq(addr, ip);

	return ptu_passed();
}

static struct ptunit_result cond_null(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode, tnt = 0xbc, taken = tnt;

	errcode = pt_query_cond_branch(NULL, &taken);
	ptu_int_eq(errcode, -pte_invalid);
	ptu_int_eq(taken, tnt);

	errcode = pt_query_cond_branch(decoder, NULL);
	ptu_int_eq(errcode, -pte_invalid);
	ptu_ptr_eq(decoder->pos, config->begin);

	return ptu_passed();
}

static struct ptunit_result cond_empty(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	int errcode, tnt = 0xbc, taken = tnt;

	decoder->pos = config->end;

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_eos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result cond(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;

	pt_encode_tnt_8(encoder, 0x02, 3);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, 0);
	ptu_int_eq(taken, 0);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, 0);
	ptu_int_eq(taken, 1);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, 0);
	ptu_int_eq(taken, 0);

	taken = tnt;
	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_eos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result cond_skip_tip_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);
	pt_encode_tnt_8(encoder, 0, 1);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result
cond_skip_tip_pge_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	pt_encode_tip_pge(encoder, 0, pt_ipc_sext_48);
	pt_encode_tnt_8(encoder, 0, 1);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result
cond_skip_tip_pgd_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	pt_encode_tnt_8(encoder, 0, 1);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result
cond_skip_fup_tip_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);
	pt_encode_tnt_8(encoder, 0, 1);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result
cond_skip_fup_tip_pgd_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	int errcode, tnt = 0xbc, taken = tnt;
	const uint8_t *pos;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);
	pt_encode_tnt_8(encoder, 0, 1);

	ptu_sync_decoder(decoder);

	errcode = pt_query_cond_branch(decoder, &taken);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);
	ptu_int_eq(taken, tnt);

	return ptu_passed();
}

static struct ptunit_result event_null(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	errcode = pt_query_event(NULL, &event);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_query_event(decoder, NULL);
	ptu_int_eq(errcode, -pte_invalid);
	ptu_ptr_eq(decoder->pos, config->begin);

	return ptu_passed();
}

static struct ptunit_result event_empty(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_config *config = &decoder->config;
	struct pt_event event;
	int errcode;

	decoder->pos = config->end;

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result event_enabled(struct ptu_decoder_fixture *dfix,
					  enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_tip_pge(encoder, packet.ip, packet.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	if (ipc == pt_ipc_suppressed)
		ptu_int_eq(errcode, -pte_bad_packet);
	else {
		ptu_int_eq(errcode, 0);
		ptu_int_eq(event.type, ptev_enabled);
		ptu_uint_eq(event.variant.enabled.ip, dfix->last_ip.ip);
	}

	return ptu_passed();
}

static struct ptunit_result
event_enabled_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_tip_pge(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result event_disabled(struct ptu_decoder_fixture *dfix,
					   enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_tip_pgd(encoder, packet.ip, packet.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.disabled.ip, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_disabled);

	return ptu_passed();
}

static struct ptunit_result
event_disabled_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_tip_pgd(encoder, 0, pt_ipc_update_32);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_async_disabled(struct ptu_decoder_fixture *dfix,
		     enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip fup, tip;
	struct pt_event event;
	int errcode;

	fup.ipc = pt_ipc_sext_48;
	fup.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &fup, &dfix->config);

	tip.ipc = ipc;
	tip.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &tip, &dfix->config);

	pt_encode_fup(encoder, fup.ip, fup.ipc);
	pt_encode_tip_pgd(encoder, tip.ip, tip.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.async_disabled.ip, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_async_disabled);
	ptu_uint_eq(event.variant.async_disabled.at, fup.ip);

	return ptu_passed();
}

static struct ptunit_result
event_async_disabled_suppressed_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_fup(encoder, 0, pt_ipc_suppressed);
	pt_encode_tip_pgd(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_bad_packet);

	return ptu_passed();
}

static struct ptunit_result
event_async_disabled_cutoff_fail_a(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t at = pt_dfix_sext_ip;
	const uint8_t *pos;
	int errcode;

	pt_encode_fup(encoder, at, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_update_16);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result
event_async_disabled_cutoff_fail_b(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_fup(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result
event_async_branch_suppressed_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_fup(encoder, 0, pt_ipc_suppressed);
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_bad_packet);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result event_async_branch(struct ptu_decoder_fixture *dfix,
					       enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip fup, tip;
	struct pt_event event;
	int errcode;

	fup.ipc = pt_ipc_sext_48;
	fup.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &fup, &dfix->config);

	tip.ipc = ipc;
	tip.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &tip, &dfix->config);

	pt_encode_fup(encoder, fup.ip, fup.ipc);
	pt_encode_tip(encoder, tip.ip, tip.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.async_branch.to, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_async_branch);
	ptu_uint_eq(event.variant.async_branch.from, fup.ip);

	return ptu_passed();
}

static struct ptunit_result
event_async_branch_cutoff_fail_a(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pos = encoder->pos;
	pt_encode_tip_pgd(encoder, 0, pt_ipc_update_16);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result
event_async_branch_cutoff_fail_b(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_fup(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result event_paging(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	pt_encode_pip(encoder, cr3);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	ptu_int_eq(event.type, ptev_paging);
	ptu_uint_eq(event.variant.paging.cr3, cr3);

	return ptu_passed();
}

static struct ptunit_result
event_paging_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_pip(encoder, 0);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_async_paging(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t to = pt_dfix_sext_ip, from = to & ~0xffffull;
	uint64_t cr3 = pt_dfix_max_cr3;
	int errcode;

	pt_encode_fup(encoder, from, pt_ipc_sext_48);
	pt_encode_pip(encoder, cr3);
	pt_encode_tip(encoder, to, pt_ipc_update_16);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, pts_event_pending);
	ptu_int_eq(event.type, ptev_async_branch);
	ptu_uint_eq(event.variant.async_branch.from, from);
	ptu_uint_eq(event.variant.async_branch.to, to);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	ptu_int_eq(event.type, ptev_async_paging);
	ptu_uint_eq(event.variant.async_paging.cr3, cr3);
	ptu_uint_eq(event.variant.async_paging.ip, to);

	return ptu_passed();
}

static struct ptunit_result
event_async_paging_suppressed(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	uint64_t from = pt_dfix_sext_ip, cr3 = pt_dfix_max_cr3;
	int errcode;

	pt_encode_fup(encoder, from, pt_ipc_sext_48);
	pt_encode_pip(encoder, cr3);
	pt_encode_tip(encoder, 0, pt_ipc_suppressed);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, pts_event_pending);
	ptu_uint_ne(event.ip_suppressed, 0);
	ptu_int_eq(event.type, ptev_async_branch);
	ptu_uint_eq(event.variant.async_branch.from, from);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	ptu_uint_ne(event.ip_suppressed, 0);
	ptu_int_eq(event.type, ptev_async_paging);
	ptu_uint_eq(event.variant.async_paging.cr3, cr3);

	return ptu_passed();
}

static struct ptunit_result
event_async_paging_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_fup(encoder, 0, pt_ipc_sext_48);
	pt_encode_pip(encoder, 0);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result event_overflow_fup(struct ptu_decoder_fixture *dfix,
					       enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_ovf(encoder);
	pt_encode_fup(encoder, packet.ip, packet.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	switch (ipc) {
	case pt_ipc_suppressed:
		ptu_int_eq(errcode, -pte_bad_packet);
		break;

	case pt_ipc_update_16:
	case pt_ipc_update_32:
		ptu_int_eq(errcode, -pte_noip);
		break;

	case pt_ipc_sext_48:
		ptu_int_eq(errcode, 0);
		ptu_int_eq(event.type, ptev_overflow);
		ptu_uint_eq(event.variant.overflow.ip, dfix->last_ip.ip);
		break;
	}

	return ptu_passed();
}

static struct ptunit_result
event_overflow_fup_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_ovf(encoder);
	pt_encode_fup(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_overflow_tip_pge(struct ptu_decoder_fixture *dfix,
		       enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	struct pt_packet_ip packet;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_ovf(encoder);
	pt_encode_tip_pge(encoder, packet.ip, packet.ipc);

	decoder->flags |= pdf_pt_disabled;

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	switch (ipc) {
	case pt_ipc_suppressed:
		ptu_int_eq(errcode, -pte_bad_packet);
		break;

	case pt_ipc_update_16:
	case pt_ipc_update_32:
		ptu_int_eq(errcode, -pte_noip);
		break;

	case pt_ipc_sext_48:
		ptu_int_eq(errcode, pts_event_pending);
		ptu_int_eq(event.type, ptev_enabled);
		ptu_uint_eq(event.variant.enabled.ip, dfix->last_ip.ip);

		errcode = pt_query_event(decoder, &event);
		ptu_int_eq(errcode, 0);
		ptu_int_eq(event.type, ptev_overflow);
		ptu_uint_eq(event.variant.overflow.ip, dfix->last_ip.ip);
	}

	return ptu_passed();
}

static struct ptunit_result
event_overflow_tip_pge_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_ovf(encoder);
	pt_encode_tip_pge(encoder, 0, pt_ipc_update_32);

	decoder->flags |= pdf_pt_disabled;

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_overflow_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_ovf(encoder);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_exec_mode_tip(struct ptu_decoder_fixture *dfix,
		    enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_mode_exec(encoder, mode);
	pt_encode_tip(encoder, packet.ip, packet.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_exec_mode);
	ptu_int_eq(event.variant.exec_mode.mode, mode);

	errcode = pt_query_uncond_branch(decoder, &addr);
	if (ipc == pt_ipc_suppressed)
		ptu_int_eq(errcode, pts_ip_suppressed);
	else {
		ptu_int_eq(errcode, 0);
		ptu_uint_eq(addr, dfix->last_ip.ip);
	}

	return ptu_passed();
}

static struct ptunit_result
event_exec_mode_tip_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_mode_exec(encoder, ptem_32bit);
	pt_encode_tip(encoder, 0, pt_ipc_update_16);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_exec_mode_tip_pge(struct ptu_decoder_fixture *dfix,
			enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	enum pt_exec_mode mode = ptem_16bit;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_mode_exec(encoder, mode);
	pt_encode_tip_pge(encoder, packet.ip, packet.ipc);

	decoder->flags |= pdf_pt_disabled;

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	if (ipc == pt_ipc_suppressed) {
		ptu_int_eq(errcode, -pte_bad_packet);
		ptu_uint_eq(addr, 0ull);
	} else {
		ptu_int_eq(errcode, pts_event_pending);
		ptu_int_eq(event.type, ptev_enabled);
		ptu_uint_eq(event.variant.enabled.ip, dfix->last_ip.ip);

		errcode = pt_query_event(decoder, &event);
		ptu_int_eq(errcode, 0);
		ptu_int_eq(event.type, ptev_exec_mode);
		ptu_int_eq(event.variant.exec_mode.mode, mode);
		ptu_uint_eq(event.variant.exec_mode.ip, dfix->last_ip.ip);
	}

	return ptu_passed();
}

static struct ptunit_result
event_exec_mode_tip_pge_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_mode_exec(encoder, ptem_16bit);
	pt_encode_tip_pge(encoder, 0, pt_ipc_sext_48);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_exec_mode_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_mode_exec(encoder, ptem_64bit);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result event_tsx_fup(struct ptu_decoder_fixture *dfix,
					  enum pt_ip_compression ipc,
					  uint8_t flags)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip fup, tip;
	struct pt_event event;
	uint64_t addr = 0;
	int errcode;

	fup.ipc = ipc;
	fup.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &fup, &dfix->config);

	tip.ipc = pt_ipc_sext_48;
	tip.ip = pt_dfix_sext_ip;

	pt_encode_mode_tsx(encoder, flags);
	pt_encode_fup(encoder, fup.ip, fup.ipc);
	pt_encode_tip(encoder, tip.ip, tip.ipc);

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.tsx.ip, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_tsx);
	ptu_int_eq(event.variant.tsx.speculative,
		   (flags & pt_mob_tsx_intx) != 0);
	ptu_int_eq(event.variant.tsx.aborted,
		   (flags & pt_mob_tsx_abrt) != 0);

	errcode = pt_query_uncond_branch(decoder, &addr);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(addr, tip.ip);

	return ptu_passed();
}

static struct ptunit_result
event_tsx_fup_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_mode_tsx(encoder, 0);
	pt_encode_fup(encoder, 0, pt_ipc_update_16);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_tsx_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_mode_tsx(encoder, 0);

	ptu_check(cutoff, decoder, encoder);
	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
event_skip_tip_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	const uint8_t *pos;
	int errcode;

	pos = encoder->pos;
	pt_encode_tip(encoder, 0, pt_ipc_sext_48);
	/* We omit the actual event - we don't get that far, anyway. */

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_bad_query);
	ptu_ptr_eq(decoder->pos, pos);

	return ptu_passed();
}

static struct ptunit_result
event_skip_tnt_8_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_tnt_8(encoder, 0, 1);
	pt_encode_tnt_8(encoder, 0, 1);
	/* We omit the actual event - we don't get that far, anyway. */

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_bad_query);
	/* The fail position depends on the fixture's header. */

	return ptu_passed();
}

static struct ptunit_result
event_skip_tnt_64_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_event event;
	int errcode;

	pt_encode_tnt_64(encoder, 0, 1);
	pt_encode_tnt_64(encoder, 0, 1);
	/* We omit the actual event - we don't get that far, anyway. */

	ptu_sync_decoder(decoder);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, -pte_bad_query);
	/* The fail position depends on the fixture's header. */

	return ptu_passed();
}

static struct ptunit_result sync_event(struct ptu_decoder_fixture *dfix,
				       enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip packet;
	struct pt_event event;
	uint64_t addr = 0ull;
	int errcode;

	packet.ipc = ipc;
	packet.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &packet, &dfix->config);

	pt_encode_psb(encoder);
	pt_encode_mode_tsx(encoder, pt_mob_tsx_intx);
	pt_encode_fup(encoder, packet.ip, packet.ipc);
	pt_encode_psbend(encoder);

	errcode = pt_sync_forward(decoder);
	ptu_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	switch (ipc) {
	case pt_ipc_suppressed:
		ptu_int_eq(errcode, (pts_event_pending | pts_ip_suppressed));
		break;

	case pt_ipc_update_16:
	case pt_ipc_update_32:
		ptu_int_eq(errcode, -pte_noip);
		return ptu_passed();

	case pt_ipc_sext_48:
		ptu_int_eq(errcode, pts_event_pending);
		ptu_uint_eq(addr, dfix->last_ip.ip);
		break;
	}

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, 0);
	ptu_uint_ne(event.status_update, 0);
	if (ipc == pt_ipc_suppressed)
		ptu_uint_ne(event.ip_suppressed, 0);
	else {
		ptu_uint_eq(event.ip_suppressed, 0);
		ptu_uint_eq(event.variant.tsx.ip, dfix->last_ip.ip);
	}
	ptu_int_eq(event.type, ptev_tsx);
	ptu_int_eq(event.variant.tsx.speculative, 1);
	ptu_int_eq(event.variant.tsx.aborted, 0);

	return ptu_passed();
}

static struct ptunit_result
sync_event_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	pt_encode_psb(encoder);
	pt_encode_psbend(encoder);

	ptu_check(cutoff, decoder, encoder);

	errcode = pt_sync_forward(decoder);
	ptu_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result
sync_event_incomplete_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	pt_encode_psb(encoder);

	errcode = pt_sync_forward(decoder);
	ptu_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result sync_ovf_event(struct ptu_decoder_fixture *dfix,
					   enum pt_ip_compression ipc)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet_ip fup, ovf;
	struct pt_event event;
	uint64_t addr = 0;
	int errcode;

	fup.ipc = pt_ipc_sext_48;
	fup.ip = pt_dfix_max_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &fup, &dfix->config);

	ovf.ipc = ipc;
	ovf.ip = pt_dfix_sext_ip;
	pt_last_ip_update_ip(&dfix->last_ip, &ovf, &dfix->config);

	pt_encode_psb(encoder);
	pt_encode_fup(encoder, fup.ip, fup.ipc);
	pt_encode_mode_tsx(encoder, 0);
	pt_encode_ovf(encoder);
	pt_encode_fup(encoder, ovf.ip, ovf.ipc);

	errcode = pt_sync_forward(decoder);
	ptu_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, pts_event_pending);
	ptu_uint_eq(addr, fup.ip);

	errcode = pt_query_event(decoder, &event);
	ptu_int_eq(errcode, pts_event_pending);
	ptu_uint_ne(event.status_update, 0);
	ptu_int_eq(event.type, ptev_tsx);
	ptu_int_eq(event.variant.tsx.speculative, 0);
	ptu_int_eq(event.variant.tsx.aborted, 0);
	ptu_uint_eq(event.variant.tsx.ip, fup.ip);

	errcode = pt_query_event(decoder, &event);
	switch (ipc) {
	case pt_ipc_suppressed:
		ptu_int_eq(errcode, -pte_bad_packet);
		return ptu_passed();

	case pt_ipc_update_16:
	case pt_ipc_update_32:
		ptu_int_eq(errcode, -pte_noip);
		return ptu_passed();

	case pt_ipc_sext_48:
		ptu_int_eq(errcode, 0);
		ptu_int_eq(event.type, ptev_overflow);
		ptu_uint_eq(event.variant.overflow.ip, dfix->last_ip.ip);
		break;
	}

	return ptu_passed();
}

static struct ptunit_result
sync_ovf_event_cutoff_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	uint64_t addr;
	int errcode;

	pt_encode_psb(encoder);
	pt_encode_ovf(encoder);

	ptu_check(cutoff, decoder, encoder);

	errcode = pt_sync_forward(decoder);
	ptu_int_eq(errcode, 0);

	errcode = pt_query_start(decoder, &addr);
	ptu_int_eq(errcode, -pte_eos);

	return ptu_passed();
}

static struct ptunit_result tsc_null_fail(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t tsc;
	int errcode;

	errcode = pt_query_time(NULL, NULL);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_query_time(decoder, NULL);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_query_time(NULL, &tsc);
	ptu_int_eq(errcode, -pte_invalid);

	return ptu_passed();
}

static struct ptunit_result tsc_initial(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t tsc;
	int errcode;

	errcode = pt_query_time(decoder, &tsc);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(tsc, 0);

	return ptu_passed();
}

static struct ptunit_result tsc(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	uint64_t tsc, exp;
	int errcode;

	exp = 0x11223344556677ull;

	decoder->tsc = exp;

	errcode = pt_query_time(decoder, &tsc);
	ptu_int_eq(errcode, 0);
	ptu_uint_eq(tsc, exp);

	return ptu_passed();
}

static struct ptunit_result ptu_dfix_init(struct ptu_decoder_fixture *dfix)
{
	struct pt_config *config = &dfix->config;
	struct pt_decoder *decoder;
	int errcode;

	(void) memset(dfix->buffer, 0, sizeof(dfix->buffer));

	errcode = pt_configure(config);
	ptu_int_eq(errcode, 0);

	config->begin = dfix->buffer;
	config->end = dfix->buffer + sizeof(dfix->buffer);

	errcode = pt_encoder_init(&dfix->encoder, config);
	ptu_int_eq(errcode, 0);

	decoder = pt_alloc_decoder(config);
	ptu_ptr(decoder);

	decoder->ip.ip = pt_dfix_bad_ip;
	decoder->ip.need_full_ip = 0;
	decoder->ip.suppressed = 0;

	dfix->decoder = decoder;
	dfix->last_ip = decoder->ip;

	if (dfix->header)
		dfix->header(dfix);

	return ptu_passed();
}

static struct ptunit_result ptu_dfix_fini(struct ptu_decoder_fixture *dfix)
{
	pt_free_decoder(dfix->decoder);
	dfix->decoder = NULL;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of an empty buffer. */
static struct ptunit_result
ptu_dfix_header_sync(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of a buffer containing packets that
 * should be skipped for unconditional indirect branch queries.
 */
static struct ptunit_result
ptu_dfix_header_uncond(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_encode_pad(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_tnt_64(encoder, 0, 2);
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of a buffer containing packets that
 * should be skipped for unconditional indirect branch queries including a PSB.
 */
static struct ptunit_result
ptu_dfix_header_uncond_psb(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;

	/* The psb must be empty since the tests won't skip status events.
	 * On the other hand, we do need to provide an address since tests
	 * may want to update last-ip, which requires a last-ip, of course.
	 */
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_psb(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_fup(encoder, pt_dfix_sext_ip, pt_ipc_sext_48);
	pt_encode_psbend(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_tnt_8(encoder, 0, 2);
	pt_encode_pad(encoder);

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of a buffer containing packets that
 * should be skipped for conditional branch queries.
 */
static struct ptunit_result
ptu_dfix_header_cond(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;

	/* The psb must be empty since the tests won't skip status events.
	 * On the other hand, we do need to provide an address since tests
	 * may want to update last-ip, which requires a last-ip, of course.
	 */
	pt_encode_pad(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_psb(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_pad(encoder);
	pt_encode_fup(encoder, pt_dfix_sext_ip, pt_ipc_sext_48);
	pt_encode_psbend(encoder);
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_pad(encoder);

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of a buffer containing packets that
 * should be skipped for event queries.
 */
static struct ptunit_result
ptu_dfix_header_event(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;

	pt_encode_pad(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

/* Synchronize the decoder at the beginnig of a buffer containing packets that
 * should be skipped for event queries including a PSB.
 */
static struct ptunit_result
ptu_dfix_header_event_psb(struct ptu_decoder_fixture *dfix)
{
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;

	/* The psb must be empty since the tests won't skip status events.
	 * On the other hand, we do need to provide an address since tests
	 * may want to update last-ip, which requires a last-ip, of course.
	 */
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_psb(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_pad(encoder);
	pt_encode_tsc(encoder, 0);
	pt_encode_fup(encoder, pt_dfix_sext_ip, pt_ipc_sext_48);
	pt_encode_psbend(encoder);
	pt_encode_cbr(encoder, 1);
	pt_encode_pad(encoder);

	/* Synchronize the decoder at the beginning of the buffer. */
	decoder->pos = decoder->config.begin;

	return ptu_passed();
}

static struct ptu_decoder_fixture dfix_raw;
static struct ptu_decoder_fixture dfix_empty;
static struct ptu_decoder_fixture dfix_uncond;
static struct ptu_decoder_fixture dfix_uncond_psb;
static struct ptu_decoder_fixture dfix_cond;
static struct ptu_decoder_fixture dfix_event;
static struct ptu_decoder_fixture dfix_event_psb;

static void init_fixtures(void)
{
	dfix_raw.init = ptu_dfix_init;
	dfix_raw.fini = ptu_dfix_fini;

	dfix_empty = dfix_raw;
	dfix_empty.header = ptu_dfix_header_sync;

	dfix_uncond = dfix_raw;
	dfix_uncond.header = ptu_dfix_header_uncond;

	dfix_uncond_psb = dfix_raw;
	dfix_uncond_psb.header = ptu_dfix_header_uncond_psb;

	dfix_cond = dfix_raw;
	dfix_cond.header = ptu_dfix_header_cond;

	dfix_event = dfix_raw;
	dfix_event.header = ptu_dfix_header_event;

	dfix_event_psb = dfix_raw;
	dfix_event_psb.header = ptu_dfix_header_event_psb;
}

int main(int argc, const char **argv)
{
	struct ptunit_suite suite;

	init_fixtures();

	suite = ptunit_mk_suite(argc, argv);

	ptu_run_f(suite, start_nosync_fail, dfix_raw);
	ptu_run_f(suite, uncond_not_synced, dfix_raw);
	ptu_run_f(suite, cond_not_synced, dfix_raw);
	ptu_run_f(suite, event_not_synced, dfix_raw);

	ptu_run_f(suite, start_off_fail, dfix_empty);

	ptu_run_f(suite, uncond_null, dfix_empty);
	ptu_run_f(suite, uncond_empty, dfix_empty);
	ptu_run_fp(suite, uncond, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, uncond, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, uncond, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, uncond, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, uncond_cutoff_fail, dfix_empty);
	ptu_run_f(suite, uncond_skip_tnt_fail, dfix_empty);
	ptu_run_f(suite, uncond_skip_tip_pge_fail, dfix_empty);
	ptu_run_f(suite, uncond_skip_tip_pgd_fail, dfix_empty);
	ptu_run_f(suite, uncond_skip_fup_tip_fail, dfix_empty);
	ptu_run_f(suite, uncond_skip_fup_tip_pgd_fail, dfix_empty);

	ptu_run_fp(suite, uncond, dfix_uncond, pt_ipc_suppressed);
	ptu_run_fp(suite, uncond, dfix_uncond, pt_ipc_update_16);
	ptu_run_fp(suite, uncond, dfix_uncond, pt_ipc_update_32);
	ptu_run_fp(suite, uncond, dfix_uncond, pt_ipc_sext_48);
	ptu_run_f(suite, uncond_cutoff_fail, dfix_uncond);
	ptu_run_f(suite, uncond_skip_tnt_fail, dfix_uncond);
	ptu_run_f(suite, uncond_skip_tip_pge_fail, dfix_uncond);
	ptu_run_f(suite, uncond_skip_tip_pgd_fail, dfix_uncond);
	ptu_run_f(suite, uncond_skip_fup_tip_fail, dfix_uncond);
	ptu_run_f(suite, uncond_skip_fup_tip_pgd_fail, dfix_uncond);

	ptu_run_fp(suite, uncond, dfix_uncond_psb, pt_ipc_suppressed);
	ptu_run_fp(suite, uncond, dfix_uncond_psb, pt_ipc_sext_48);
	ptu_run_f(suite, uncond_cutoff_fail, dfix_uncond_psb);
	ptu_run_f(suite, uncond_skip_tnt_fail, dfix_uncond_psb);
	ptu_run_f(suite, uncond_skip_tip_pge_fail, dfix_uncond_psb);
	ptu_run_f(suite, uncond_skip_tip_pgd_fail, dfix_uncond_psb);
	ptu_run_f(suite, uncond_skip_fup_tip_fail, dfix_uncond_psb);
	ptu_run_f(suite, uncond_skip_fup_tip_pgd_fail, dfix_uncond_psb);

	ptu_run_f(suite, cond_null, dfix_empty);
	ptu_run_f(suite, cond_empty, dfix_empty);
	ptu_run_f(suite, cond, dfix_empty);
	ptu_run_f(suite, cond_skip_tip_fail, dfix_empty);
	ptu_run_f(suite, cond_skip_tip_pge_fail, dfix_empty);
	ptu_run_f(suite, cond_skip_tip_pgd_fail, dfix_empty);
	ptu_run_f(suite, cond_skip_fup_tip_fail, dfix_empty);
	ptu_run_f(suite, cond_skip_fup_tip_pgd_fail, dfix_empty);

	ptu_run_f(suite, cond, dfix_cond);
	ptu_run_f(suite, cond_skip_tip_fail, dfix_cond);
	ptu_run_f(suite, cond_skip_tip_pge_fail, dfix_cond);
	ptu_run_f(suite, cond_skip_tip_pgd_fail, dfix_cond);
	ptu_run_f(suite, cond_skip_fup_tip_fail, dfix_cond);
	ptu_run_f(suite, cond_skip_fup_tip_pgd_fail, dfix_cond);

	ptu_run_f(suite, event_null, dfix_empty);
	ptu_run_f(suite, event_empty, dfix_empty);
	ptu_run_fp(suite, event_enabled, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_enabled, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_enabled, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_enabled, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_enabled_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_disabled, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_disabled, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_disabled, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_disabled, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_disabled_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_async_disabled, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_disabled, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_async_disabled, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_async_disabled, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_async_disabled_suppressed_fail, dfix_empty);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_a, dfix_empty);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_b, dfix_empty);
	ptu_run_fp(suite, event_async_branch, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_branch, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_async_branch, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_async_branch, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_async_branch_suppressed_fail, dfix_empty);
	ptu_run_f(suite, event_async_branch_cutoff_fail_a, dfix_empty);
	ptu_run_f(suite, event_async_branch_cutoff_fail_b, dfix_empty);
	ptu_run_f(suite, event_paging, dfix_empty);
	ptu_run_f(suite, event_paging_cutoff_fail, dfix_empty);
	ptu_run_f(suite, event_async_paging, dfix_empty);
	ptu_run_f(suite, event_async_paging_suppressed, dfix_empty);
	ptu_run_f(suite, event_async_paging_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_overflow_fup, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_overflow_fup, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_overflow_fup, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_overflow_fup, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_overflow_fup_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_empty,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_overflow_tip_pge_cutoff_fail, dfix_empty);
	ptu_run_f(suite, event_overflow_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_empty,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_empty,
		   pt_ipc_update_16);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_empty,
		   pt_ipc_update_32);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_pge_cutoff_fail, dfix_empty);
	ptu_run_f(suite, event_exec_mode_cutoff_fail, dfix_empty);
	ptu_run_fp(suite, event_tsx_fup, dfix_empty, pt_ipc_suppressed,
		   pt_mob_tsx_intx);
	ptu_run_fp(suite, event_tsx_fup, dfix_empty, pt_ipc_update_16, 0);
	ptu_run_fp(suite, event_tsx_fup, dfix_empty, pt_ipc_update_32,
		   pt_mob_tsx_intx);
	ptu_run_fp(suite, event_tsx_fup, dfix_empty, pt_ipc_sext_48, 0);
	ptu_run_f(suite, event_tsx_fup_cutoff_fail, dfix_empty);
	ptu_run_f(suite, event_tsx_cutoff_fail, dfix_empty);
	ptu_run_f(suite, event_skip_tip_fail, dfix_empty);
	ptu_run_f(suite, event_skip_tnt_8_fail, dfix_empty);
	ptu_run_f(suite, event_skip_tnt_64_fail, dfix_empty);
	ptu_run_fp(suite, sync_event, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, sync_event, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, sync_event, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, sync_event, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, sync_event_cutoff_fail, dfix_empty);
	ptu_run_f(suite, sync_event_incomplete_fail, dfix_empty);
	ptu_run_fp(suite, sync_ovf_event, dfix_empty, pt_ipc_suppressed);
	ptu_run_fp(suite, sync_ovf_event, dfix_empty, pt_ipc_update_16);
	ptu_run_fp(suite, sync_ovf_event, dfix_empty, pt_ipc_update_32);
	ptu_run_fp(suite, sync_ovf_event, dfix_empty, pt_ipc_sext_48);
	ptu_run_f(suite, sync_ovf_event_cutoff_fail, dfix_empty);

	ptu_run_fp(suite, event_enabled, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_enabled, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_enabled, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_enabled, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_enabled_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_disabled, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_disabled, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_disabled, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_disabled, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_disabled_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_async_disabled, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_disabled, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_async_disabled, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_async_disabled, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_async_disabled_suppressed_fail, dfix_event);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_a, dfix_event);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_b, dfix_event);
	ptu_run_fp(suite, event_async_branch, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_branch, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_async_branch, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_async_branch, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_async_branch_suppressed_fail, dfix_event);
	ptu_run_f(suite, event_async_branch_cutoff_fail_a, dfix_event);
	ptu_run_f(suite, event_async_branch_cutoff_fail_b, dfix_event);
	ptu_run_f(suite, event_paging, dfix_event);
	ptu_run_f(suite, event_paging_cutoff_fail, dfix_event);
	ptu_run_f(suite, event_async_paging, dfix_event);
	ptu_run_f(suite, event_async_paging_suppressed, dfix_event);
	ptu_run_f(suite, event_async_paging_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_overflow_fup, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_overflow_fup, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_overflow_fup, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_overflow_fup, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_overflow_fup_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_event,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_overflow_tip_pge, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_overflow_tip_pge_cutoff_fail, dfix_event);
	ptu_run_f(suite, event_overflow_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_event,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_event,
		   pt_ipc_update_16);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_event,
		   pt_ipc_update_32);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_pge_cutoff_fail, dfix_event);
	ptu_run_f(suite, event_exec_mode_cutoff_fail, dfix_event);
	ptu_run_fp(suite, event_tsx_fup, dfix_event, pt_ipc_suppressed, 0);
	ptu_run_fp(suite, event_tsx_fup, dfix_event, pt_ipc_update_16,
		   pt_mob_tsx_intx);
	ptu_run_fp(suite, event_tsx_fup, dfix_event, pt_ipc_update_32, 0);
	ptu_run_fp(suite, event_tsx_fup, dfix_event, pt_ipc_sext_48,
		   pt_mob_tsx_intx);
	ptu_run_f(suite, event_tsx_fup_cutoff_fail, dfix_event);
	ptu_run_f(suite, event_tsx_cutoff_fail, dfix_event);
	ptu_run_f(suite, event_skip_tip_fail, dfix_event);
	ptu_run_f(suite, event_skip_tnt_8_fail, dfix_event);
	ptu_run_f(suite, event_skip_tnt_64_fail, dfix_event);
	ptu_run_fp(suite, sync_event, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, sync_event, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, sync_event, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, sync_event, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, sync_event_cutoff_fail, dfix_event);
	ptu_run_f(suite, sync_event_incomplete_fail, dfix_event);
	ptu_run_fp(suite, sync_ovf_event, dfix_event, pt_ipc_suppressed);
	ptu_run_fp(suite, sync_ovf_event, dfix_event, pt_ipc_update_16);
	ptu_run_fp(suite, sync_ovf_event, dfix_event, pt_ipc_update_32);
	ptu_run_fp(suite, sync_ovf_event, dfix_event, pt_ipc_sext_48);
	ptu_run_f(suite, sync_ovf_event_cutoff_fail, dfix_event);

	ptu_run_fp(suite, event_enabled, dfix_event_psb, pt_ipc_suppressed);
	ptu_run_fp(suite, event_enabled, dfix_event_psb, pt_ipc_sext_48);
	ptu_run_f(suite, event_enabled_cutoff_fail, dfix_event_psb);
	ptu_run_fp(suite, event_disabled, dfix_event_psb, pt_ipc_suppressed);
	ptu_run_fp(suite, event_disabled, dfix_event_psb, pt_ipc_sext_48);
	ptu_run_f(suite, event_disabled_cutoff_fail, dfix_event_psb);
	ptu_run_fp(suite, event_async_disabled, dfix_event_psb,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_disabled, dfix_event_psb,
		   pt_ipc_update_16);
	ptu_run_fp(suite, event_async_disabled, dfix_event_psb,
		   pt_ipc_update_32);
	ptu_run_fp(suite, event_async_disabled, dfix_event_psb,
		   pt_ipc_sext_48);
	ptu_run_f(suite, event_async_disabled_suppressed_fail, dfix_event_psb);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_a, dfix_event_psb);
	ptu_run_f(suite, event_async_disabled_cutoff_fail_b, dfix_event_psb);
	ptu_run_fp(suite, event_async_branch, dfix_event_psb,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_async_branch, dfix_event_psb, pt_ipc_update_16);
	ptu_run_fp(suite, event_async_branch, dfix_event_psb, pt_ipc_update_32);
	ptu_run_fp(suite, event_async_branch, dfix_event_psb, pt_ipc_sext_48);
	ptu_run_f(suite, event_async_branch_suppressed_fail, dfix_event_psb);
	ptu_run_f(suite, event_async_branch_cutoff_fail_a, dfix_event_psb);
	ptu_run_f(suite, event_async_branch_cutoff_fail_b, dfix_event_psb);
	ptu_run_f(suite, event_paging, dfix_event_psb);
	ptu_run_f(suite, event_paging_cutoff_fail, dfix_event_psb);
	ptu_run_f(suite, event_async_paging, dfix_event_psb);
	ptu_run_f(suite, event_async_paging_suppressed, dfix_event_psb);
	ptu_run_f(suite, event_async_paging_cutoff_fail, dfix_event_psb);
	ptu_run_f(suite, event_overflow_cutoff_fail, dfix_event_psb);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event_psb,
		   pt_ipc_suppressed);
	ptu_run_fp(suite, event_exec_mode_tip, dfix_event_psb, pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_cutoff_fail, dfix_event_psb);
	ptu_run_fp(suite, event_exec_mode_tip_pge, dfix_event_psb,
		   pt_ipc_sext_48);
	ptu_run_f(suite, event_exec_mode_tip_pge_cutoff_fail, dfix_event_psb);
	ptu_run_f(suite, event_exec_mode_cutoff_fail, dfix_event_psb);
	ptu_run_fp(suite, event_tsx_fup, dfix_event_psb, pt_ipc_suppressed, 0);
	ptu_run_fp(suite, event_tsx_fup, dfix_event_psb, pt_ipc_sext_48,
		   pt_mob_tsx_intx);
	ptu_run_f(suite, event_tsx_fup_cutoff_fail, dfix_event_psb);
	ptu_run_f(suite, event_tsx_cutoff_fail, dfix_event_psb);
	ptu_run_f(suite, event_skip_tip_fail, dfix_event_psb);
	ptu_run_f(suite, event_skip_tnt_8_fail, dfix_event_psb);
	ptu_run_f(suite, event_skip_tnt_64_fail, dfix_event_psb);

	ptu_run_f(suite, tsc_null_fail, dfix_empty);
	ptu_run_f(suite, tsc_initial, dfix_empty);
	ptu_run_f(suite, tsc, dfix_empty);

	ptunit_report(&suite);
	return suite.nr_fails;
}
