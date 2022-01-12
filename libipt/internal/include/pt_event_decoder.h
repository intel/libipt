/*
 * Copyright (c) 2018-2022, Intel Corporation
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

#ifndef PT_EVENT_DECODER_H
#define PT_EVENT_DECODER_H

#include "pt_packet_decoder.h"
#include "pt_event_queue.h"
#include "pt_last_ip.h"
#include "pt_time.h"

#include "intel-pt.h"


/* An Intel PT event decoder.
 *
 * It decodes sequences of Intel PT packets into events.
 */
struct pt_event_decoder {
	/* The Intel PT packet decoder. */
	struct pt_packet_decoder pacdec;

	/* The configuration flags.
	 *
	 * Those are our flags set by the user.  In @pacdec.config.flags, we
	 * set the flags we need for the packet decoder.
	 */
	struct pt_conf_flags flags;

	/* The current packet to be processed.
	 *
	 * This will be valid as long as there are packets available.  It will
	 * be of type ppt_invalid when the packet decoder returned an error
	 * (which will be stored in @status).
	 *
	 * The decoder starts by reading the first packet after synchronizing
	 * onto the trace stream.
	 *
	 * When it is done processing a packet, it fetches the next packet for
	 * the next iteration.
	 */
	struct pt_packet packet;

	/* The last-ip. */
	struct pt_last_ip ip;

	/* Timing information. */
	struct pt_time time;

	/* Timing calibration. */
	struct pt_time_cal tcal;

	/* Pending (incomplete) events. */
	struct pt_event_queue evq;

	/* The current event. */
	struct pt_event *event;

	/* The last status of the packet decoder.
	 *
	 * It will be zero most of the time.  Since we fetch new packets at the
	 * end of an iteration, we need to store the status until the next
	 * pt_evt_next() call.
	 */
	int status;

	/* A collection of flags saying whether:
	 *
	 * - tracing is enabled.
	 */
	unsigned int enabled:1;

	/* - the current packet is already bound and must not be interpreted as
	 *   standalone packet once events have been processed.
	 */
	unsigned int bound:1;
};


/* Initialize the event decoder.
 *
 * Returns zero on success, a negative error code otherwise.
 */
extern int pt_evt_decoder_init(struct pt_event_decoder *decoder,
			       const struct pt_config *config);

/* Finalize the event decoder. */
extern void pt_evt_decoder_fini(struct pt_event_decoder *decoder);

static inline const struct pt_config *
pt_evt_config(const struct pt_event_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_pkt_config(&decoder->pacdec);
}

static inline const uint8_t *pt_evt_pos(const struct pt_event_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_pkt_pos(&decoder->pacdec);
}

static inline const uint8_t *pt_evt_end(const struct pt_event_decoder *decoder)
{
	const struct pt_config *config;

	config = pt_evt_config(decoder);
	if (!config)
		return NULL;

	return config->end;
}

#endif /* PT_EVENT_DECODER_H */
