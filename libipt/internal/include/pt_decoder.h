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

#ifndef __PT_DECODER_H__
#define __PT_DECODER_H__

#include "pt_last_ip.h"
#include "pt_tnt_cache.h"
#include "pt_time.h"
#include "pt_event_queue.h"

#include "intel-pt.h"

#include <stdint.h>

struct pt_decoder_function;


/* Intel(R) Processor Trace decoder flags. */
enum pt_decoder_flag {
	/* Tracing has temporarily been disabled. */
	pdf_pt_disabled		= 1 << 0,

	/* The packet will be consumed after all events have been processed. */
	pdf_consume_packet	= 1 << 1
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

	/* Timing information. */
	struct pt_time time;

	/* Pending (incomplete) events. */
	struct pt_event_queue evq;

	/* The current event. */
	struct pt_event *event;
};

/* Initialize the decoder.
 *
 * Returns zero on success, a negative error code otherwise.
 */
extern int pt_decoder_init(struct pt_decoder *, const struct pt_config *);

/* Finalize the decoder. */
extern void pt_decoder_fini(struct pt_decoder *);

/* Check if decoding the next decoder function will result in an event.
 *
 * Returns 1 if it will result in an event.
 * Returns 0 if it will not result in an event.
 * Returns -pte_invalid if @decoder is NULL.
 */
extern int pt_will_event(const struct pt_decoder *decoder);

/* Reset the decoder state.
 *
 * This resets the cache fields of the decoder state. It does not modify
 * buffer-related fields.
 */
extern void pt_reset(struct pt_decoder *);

#endif /* __PT_DECODER_H__ */
