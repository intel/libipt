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

#ifndef __PT_STATE_H__
#define __PT_STATE_H__

#include "pt_opcode.h"
#include "pt_query.h"
#include "pt_error.h"
#include "pt_config.h"

#include "pt_last_ip.h"
#include "pt_tnt_cache.h"

#include <stdint.h>

struct pt_decoder_function;


/* Intel(R) Processor Trace decoder flags. */
enum pt_decoder_flag {
	/* Tracing has temporarily been disabled. */
	pdf_pt_disabled		= 1 << 0,

	/* The packet will be consumed after all events have been processed. */
	pdf_consume_packet	= 1 << 1,

	/* The current event is for status update. */
	pdf_status_event	= 1 << 2
};

/* Intel(R) Processor Trace event bindings.
 *
 * Events are grouped by the packet the event packet binds to.
 */
enum pt_event_binding {
	evb_psbend,
	evb_tip,
	evb_fup,

	evb_max,

	/* The maximal number of pending events - should be a power of two. */
	evb_max_pend = 8
};

struct pt_decoder {
	/* The decoder configuration. */
	struct pt_config config;

	/* The current position in the trace buffer. */
	const uint8_t *pos;

	/* The position of the last PSB packet. */
	const uint8_t *sync;

	/* The decoding function for the next packet. */
	const struct pt_decoder_function *next;

	/* The last-ip. */
	struct pt_last_ip ip;

	/* The cached tnt indicators. */
	struct pt_tnt_cache tnt;

	/* A bit-vector of decoder flags. */
	uint64_t flags;

	/* The last event. */
	struct pt_event *event;

	/* A series of pending event queues. */
	struct pt_event ev_pend[evb_max][evb_max_pend];

	/* The begin and end indices for the above event queues. */
	uint8_t ev_begin[evb_max];
	uint8_t ev_end[evb_max];

	/* A standalone event that is reported immediately. */
	struct pt_event ev_immed;

	/* The current time stamp count. */
	uint64_t tsc;
};


static inline const uint8_t *pt_begin(const struct pt_decoder *decoder)
{
	return decoder->config.begin;
}

static inline const uint8_t *pt_end(const struct pt_decoder *decoder)
{
	return decoder->config.end;
}

static inline int pt_check_bounds(const struct pt_decoder *decoder, int size)
{
	const uint8_t *begin, *end;

	if (size < 0)
		return -pte_internal;

	begin = decoder->pos;
	end = pt_end(decoder);

	if (end < begin)
		return -pte_internal;

	begin += size;
	if (end < begin)
		return -pte_eos;

	return 0;
}

static inline int pt_check_sync(const struct pt_decoder *decoder)
{
	const uint8_t *pos, *begin, *end;

	if (!decoder)
		return -pte_invalid;

	begin = pt_begin(decoder);
	end = pt_end(decoder);
	pos = decoder->pos;

	if (end < begin)
		return -pte_internal;

	if (!pos)
		return -pte_nosync;

	if (pos < begin)
		return -pte_eos;

	if (end < pos)
		return -pte_eos;

	return 0;
}

/* Return the pt_status_flag bit-vector for the current decoder state.
 *
 * Returns a bit-vector of status flags on success.
 * Returns -pte_invalid if no decoder is given.
 */
extern int pt_status_flags(struct pt_decoder *);

/* Reset the decoder state.
 *
 * This resets the cache fields of the decoder state. It does not modify
 * buffer-related fields.
 */
extern void pt_reset(struct pt_decoder *);

/* Enqueue an event.
 *
 * Adds a new event to the event queue for binding @evb.
 *
 * Returns a pointer to the queued event on success.
 * Returns NULL if the queue is full.
 */
extern struct pt_event *pt_enqueue_event(struct pt_decoder *,
					 enum pt_event_binding evb);

/* Dequeue an event.
 *
 * Removes the first event from the queue for binding @evb and returns a pointer
 * to it. The pointer is valid until the next dequeue operation.
 *
 * Returns a pointer to the dequeued event on success.
 * Returns NULL if the queue is empty.
 */
extern struct pt_event *pt_dequeue_event(struct pt_decoder *,
					 enum pt_event_binding evb);

/* Clear an event queue.
 *
 * Removes all events from the event queue for binding @evb.
 */
extern void pt_discard_events(struct pt_decoder *,
			      enum pt_event_binding evb);

/* Check whether events are pending.
 *
 * Returns non-zero if there is at least one event in the event queue
 * for binding @evb.
 * Returns 0 if the event queue for binging @evb is empty.
 * Returns a negative error code otherwise.
 */
extern int pt_event_pending(struct pt_decoder *,
			    enum pt_event_binding evb);

/* Search for an event of a specific type.
 *
 * Returns a pointer to an event of type @type in the event queue for
 * binding @evb. If there is more than one event of type @type, it is
 * undefined to which of these events the returned pointer points.
 */
extern struct pt_event *pt_find_event(struct pt_decoder *,
				      enum pt_event_type type,
				      enum pt_event_binding evb);

#endif /* __PT_STATE_H__ */
