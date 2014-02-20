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
#include "pt_packet_decode.h"

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

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);

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

int pt_get_decoder_pos(struct pt_decoder *decoder, uint64_t *offset)
{
	const uint8_t *raw, *begin;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = pt_begin(decoder);
	if (!begin)
		return -pte_invalid;

	raw = decoder->pos;
	if (!raw)
		return -pte_nosync;

	*offset = raw - begin;

	return 0;
}

int pt_get_decoder_sync(struct pt_decoder *decoder, uint64_t *offset)
{
	const uint8_t *sync, *begin;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = pt_begin(decoder);
	if (!begin)
		return -pte_invalid;

	sync = decoder->sync;
	if (!sync)
		return -pte_nosync;

	*offset = sync - begin;

	return 0;
}

const uint8_t *pt_get_decoder_raw(const struct pt_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return decoder->pos;
}

const uint8_t *pt_get_decoder_begin(const struct pt_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_begin(decoder);
}

const uint8_t *pt_get_decoder_end(const struct pt_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_end(decoder);
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
		return pt_event_pending(decoder, evb_psbend);

	if (dfun->flags & pdff_tip)
		return pt_event_pending(decoder, evb_tip);

	if (dfun->flags & pdff_fup)
		return pt_event_pending(decoder, evb_fup);

	return 0;
}

void pt_reset(struct pt_decoder *decoder)
{
	int evb;

	if (!decoder)
		return;

	decoder->flags = 0;
	decoder->event = NULL;
	decoder->tsc = 0;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);

	for (evb = 0; evb < evb_max; ++evb)
		pt_discard_events(decoder, (enum pt_event_binding) evb);
}

static inline uint8_t pt_queue_inc(uint8_t idx)
{
	idx += 1;
	idx %= evb_max_pend;

	return idx;
}

struct pt_event *pt_standalone_event(struct pt_decoder *decoder)
{
	struct pt_event *event;

	if (!decoder)
		return NULL;

	event = &decoder->ev_immed;

	event->ip_suppressed = 0;
	event->status_update = 0;

	return event;
}

struct pt_event *pt_enqueue_event(struct pt_decoder *decoder,
				  enum pt_event_binding evb)
{
	struct pt_event *ev;
	uint8_t begin, end, gap;

	if (!decoder)
		return NULL;

	if (evb_max <= evb)
		return NULL;

	begin = decoder->ev_begin[evb];
	end = decoder->ev_end[evb];

	if (evb_max_pend <= begin)
		return NULL;

	if (evb_max_pend <= end)
		return NULL;

	ev = &decoder->ev_pend[evb][end];
	ev->ip_suppressed = 0;
	ev->status_update = 0;

	end = pt_queue_inc(end);
	gap = pt_queue_inc(end);

	/* Leave a gap so we don't overwrite the last dequeued event. */
	if (begin == gap)
		return NULL;

	decoder->ev_end[evb] = end;

	/* This is not strictly necessary. */
	(void) memset(ev, 0, sizeof(*ev));

	return ev;
}

struct pt_event *pt_dequeue_event(struct pt_decoder *decoder,
				  enum pt_event_binding evb)
{
	struct pt_event *ev;
	uint8_t begin, end;

	if (!decoder)
		return NULL;

	if (evb_max <= evb)
		return NULL;

	begin = decoder->ev_begin[evb];
	end = decoder->ev_end[evb];

	if (evb_max_pend <= begin)
		return NULL;

	if (evb_max_pend <= end)
		return NULL;

	if (begin == end)
		return NULL;

	ev = &decoder->ev_pend[evb][begin];

	decoder->ev_begin[evb] = pt_queue_inc(begin);

	return ev;
}

void pt_discard_events(struct pt_decoder *decoder,
		       enum pt_event_binding evb)
{
	if (!decoder)
		return;

	if (evb_max <= evb)
		return;

	decoder->ev_begin[evb] = 0;
	decoder->ev_end[evb] = 0;
}

int pt_event_pending(const struct pt_decoder *decoder,
		     enum pt_event_binding evb)
{
	uint8_t begin, end;

	if (!decoder)
		return -pte_internal;

	if (evb_max <= evb)
		return -pte_internal;

	begin = decoder->ev_begin[evb];
	end = decoder->ev_end[evb];

	if (evb_max_pend <= begin)
		return -pte_internal;

	if (evb_max_pend <= end)
		return -pte_internal;

	return begin != end;
}

struct pt_event *pt_find_event(struct pt_decoder *decoder,
			       enum pt_event_type type,
			       enum pt_event_binding evb)
{
	uint8_t begin, end;

	if (!decoder)
		return NULL;

	if (evb_max <= evb)
		return NULL;

	begin = decoder->ev_begin[evb];
	end = decoder->ev_end[evb];

	if (evb_max_pend <= begin)
		return NULL;

	if (evb_max_pend <= end)
		return NULL;

	for (; begin != end; begin = pt_queue_inc(begin)) {
		struct pt_event *ev;

		ev = &decoder->ev_pend[evb][begin];
		if (ev->type == type)
			return ev;
	}

	return NULL;
}
