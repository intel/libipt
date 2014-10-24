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

#include "pt_decoder.h"
#include "pt_decoder_function.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <string.h>


int pt_decoder_init(struct pt_decoder *decoder, const struct pt_config *config)
{
	if (!decoder || !config)
		return -pte_invalid;

	if (config->size != sizeof(*config))
		return -pte_bad_config;

	if (!config->begin || !config->end)
		return -pte_bad_config;

	if (config->end < config->begin)
		return -pte_bad_config;

	memset(decoder, 0, sizeof(*decoder));

	decoder->config = *config;
	decoder->flags = pdf_pt_disabled;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->time);
	pt_evq_init(&decoder->evq);

	return 0;
}

struct pt_decoder *pt_alloc_decoder(const struct pt_config *config)
{
	struct pt_decoder *decoder;
	int errcode;

	decoder = (struct pt_decoder *) malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		decoder = NULL;
	}

	return decoder;
}

void pt_decoder_fini(struct pt_decoder *decoder)
{
	/* Nothing to do. */
}

void pt_free_decoder(struct pt_decoder *decoder)
{
	free(decoder);
}

int pt_will_event(const struct pt_decoder *decoder)
{
	const struct pt_decoder_function *dfun;

	if (!decoder)
		return -pte_invalid;

	dfun = decoder->next;
	if (!dfun)
		return 0;

	if (dfun->flags & pdff_event)
		return 1;

	if (dfun->flags & pdff_psbend)
		return pt_evq_pending(&decoder->evq, evb_psbend);

	if (dfun->flags & pdff_tip)
		return pt_evq_pending(&decoder->evq, evb_tip);

	if (dfun->flags & pdff_fup)
		return pt_evq_pending(&decoder->evq, evb_fup);

	return 0;
}

void pt_reset(struct pt_decoder *decoder)
{
	if (!decoder)
		return;

	decoder->flags = pdf_pt_disabled;
	decoder->event = NULL;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->time);
	pt_evq_init(&decoder->evq);
}
