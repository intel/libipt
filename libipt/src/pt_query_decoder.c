/*
 * Copyright (c) 2014, Intel Corporation
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

#include "pt_query_decoder.h"
#include "pt_sync.h"


int pt_qry_decoder_init(struct pt_query_decoder *decoder,
			const struct pt_config *config)
{
	if (!decoder)
		return -pte_invalid;

	return pt_decoder_init(&decoder->decoder, config);
}

struct pt_query_decoder *pt_qry_alloc_decoder(const struct pt_config *config)
{
	struct pt_query_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_qry_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_qry_decoder_fini(struct pt_query_decoder *decoder)
{
	if (!decoder)
		return;

	pt_decoder_fini(&decoder->decoder);
}

void pt_qry_free_decoder(struct pt_query_decoder *decoder)
{
	pt_qry_decoder_fini(decoder);
	free(decoder);
}

int pt_qry_sync_forward(struct pt_query_decoder *qry, uint64_t *ip)
{
	struct pt_decoder *decoder;
	const uint8_t *pos, *sync;
	int errcode;

	if (!qry)
		return -pte_invalid;

	decoder = &qry->decoder;

	sync = decoder->sync;
	pos = decoder->pos;
	if (!pos)
		pos = decoder->config.begin;

	if (pos == sync)
		pos += ptps_psb;

	errcode = pt_sync_forward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->sync = sync;
	decoder->pos = sync;

	pt_reset(decoder);

	return pt_query_start(decoder, ip);
}

int pt_qry_sync_backward(struct pt_query_decoder *qry, uint64_t *ip)
{
	struct pt_decoder *decoder;
	const uint8_t *pos, *sync;
	int errcode;

	if (!qry)
		return -pte_invalid;

	decoder = &qry->decoder;

	pos = decoder->sync;
	if (!pos)
		pos = decoder->config.end;

	errcode = pt_sync_backward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->sync = sync;
	decoder->pos = sync;

	pt_reset(decoder);

	return pt_query_start(decoder, ip);
}

int pt_qry_get_offset(struct pt_query_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_get_decoder_pos(&decoder->decoder, offset);
}

int pt_qry_get_sync_offset(struct pt_query_decoder *decoder,
			   uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_get_decoder_sync(&decoder->decoder, offset);
}

int pt_qry_cond_branch(struct pt_query_decoder *decoder, int *tnt)
{
	if (!decoder)
		return -pte_invalid;

	return pt_query_cond_branch(&decoder->decoder, tnt);
}

int pt_qry_indirect_branch(struct pt_query_decoder *decoder, uint64_t *pos)
{
	if (!decoder)
		return -pte_invalid;

	return pt_query_uncond_branch(&decoder->decoder, pos);
}

int pt_qry_event(struct pt_query_decoder *decoder, struct pt_event *event)
{
	if (!decoder)
		return -pte_invalid;

	return pt_query_event(&decoder->decoder, event);
}

int pt_qry_time(struct pt_query_decoder *decoder, uint64_t *time)
{
	if (!decoder)
		return -pte_invalid;

	return pt_query_time(&decoder->decoder, time);
}

int pt_qry_core_bus_ratio(struct pt_query_decoder *decoder, uint32_t *cbr)
{
	if (!decoder)
		return -pte_invalid;

	return pt_query_core_bus_ratio(&decoder->decoder, cbr);
}
