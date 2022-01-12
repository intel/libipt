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

#ifndef PT_PACKET_DECODER_H
#define PT_PACKET_DECODER_H

#include "intel-pt.h"


/* An Intel PT packet decoder. */
struct pt_packet_decoder {
	/* The decoder configuration. */
	struct pt_config config;

	/* The current position in the trace buffer. */
	const uint8_t *pos;

	/* The position of the last PSB packet. */
	const uint8_t *sync;
};


/* Initialize the packet decoder.
 *
 * Returns zero on success, a negative error code otherwise.
 */
extern int pt_pkt_decoder_init(struct pt_packet_decoder *,
			       const struct pt_config *);

/* Finalize the packet decoder. */
extern void pt_pkt_decoder_fini(struct pt_packet_decoder *);

static inline const struct pt_config *
pt_pkt_config(const struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return &decoder->config;
}

static inline const uint8_t *
pt_pkt_pos(const struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return decoder->pos;
}

static inline const uint8_t *
pt_pkt_end(const struct pt_packet_decoder *decoder)
{
	const struct pt_config *config;

	config = pt_pkt_config(decoder);
	if (!config)
		return NULL;

	return config->end;
}

#endif /* PT_PACKET_DECODER_H */
