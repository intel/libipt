/*
 * Copyright (c) 2014-2022, Intel Corporation
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

#ifndef PT_QUERY_DECODER_H
#define PT_QUERY_DECODER_H

#include "pt_event_decoder.h"
#include "pt_tnt_cache.h"

#include "intel-pt.h"


/* An Intel PT query decoder. */
struct pt_query_decoder {
	/* The Intel PT event decoder. */
	struct pt_event_decoder evdec;

	/* The configuration flags.
	 *
	 * Those are our flags set by the user.  In @evdec.config.flags, we set
	 * the flags we need for the event decoder.
	 */
	struct pt_conf_flags flags;

	/* The cached tnt indicators. */
	struct pt_tnt_cache tnt;

	/* The time at the last query (before reading ahead). */
	struct pt_time last_time;

	/* The current event to be processed.
	 *
	 * This will be valid as long as there are events available, i.e. until
	 * @status is not negative.
	 *
	 * The decoder starts by reading the first event after synchronizing
	 * onto the trace stream.
	 *
	 * When it is done processing an event, it fetches the next event for
	 * the next iteration.
	 */
	struct pt_event event;

	/* The last status of the event decoder.
	 *
	 * It will be zero most of the time.  Since we fetch new events at the
	 * end of an iteration, we need to store the status until the next
	 * pt_qry_*() call.
	 */
	int status;
};

/* Initialize the query decoder.
 *
 * Returns zero on success, a negative error code otherwise.
 */
extern int pt_qry_decoder_init(struct pt_query_decoder *,
			       const struct pt_config *);

/* Finalize the query decoder. */
extern void pt_qry_decoder_fini(struct pt_query_decoder *);

static inline const struct pt_config *
pt_qry_config(const struct pt_query_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_evt_config(&decoder->evdec);
}

static inline const uint8_t *pt_qry_pos(const struct pt_query_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_evt_pos(&decoder->evdec);
}

#endif /* PT_QUERY_DECODER_H */
