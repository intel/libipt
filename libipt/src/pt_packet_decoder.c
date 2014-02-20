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

#include "pt_packet_decoder.h"
#include "pt_packet_decode.h"


int pt_pkt_decoder_init(struct pt_packet_decoder *decoder,
			const struct pt_config *config)
{
	if (!decoder)
		return -pte_invalid;

	return pt_decoder_init(&decoder->decoder, config);
}

struct pt_packet_decoder *pt_pkt_alloc_decoder(const struct pt_config *config)
{
	struct pt_packet_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_pkt_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_pkt_decoder_fini(struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return;

	pt_decoder_fini(&decoder->decoder);
}

void pt_pkt_free_decoder(struct pt_packet_decoder *decoder)
{
	pt_pkt_decoder_fini(decoder);
	free(decoder);
}

int pt_pkt_sync_forward(struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return -pte_invalid;

	return pt_sync_forward(&decoder->decoder);
}

int pt_pkt_sync_backward(struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return -pte_invalid;

	return pt_sync_backward(&decoder->decoder);
}

int pt_pkt_sync_set(struct pt_packet_decoder *decoder, uint64_t offset)
{
	const uint8_t *begin, *end, *pos;

	if (!decoder)
		return -pte_invalid;

	begin = pt_begin(&decoder->decoder);
	end = pt_end(&decoder->decoder);
	pos = begin + offset;

	if (end < pos || pos < begin)
		return -pte_invalid;

	decoder->decoder.sync = pos;
	decoder->decoder.pos = pos;

	pt_reset(&decoder->decoder);

	return 0;
}

const uint8_t *pt_pkt_get_pos(struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return decoder->decoder.pos;
}

int pt_pkt_get_offset(struct pt_packet_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_get_decoder_pos(&decoder->decoder, offset);
}

int pt_pkt_get_sync_offset(struct pt_packet_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_get_decoder_sync(&decoder->decoder, offset);
}

int pt_pkt_next(struct pt_packet_decoder *decoder, struct pt_packet *packet)
{
	const struct pt_decoder_function *dfun;
	int errcode, size;

	if (!packet || !decoder)
		return -pte_invalid;

	errcode = pt_fetch_decoder(&decoder->decoder);
	if (errcode < 0)
		return errcode;

	dfun = decoder->decoder.next;
	if (!dfun)
		return -pte_internal;

	if (!dfun->packet)
		return -pte_internal;

	size = dfun->packet(packet, &decoder->decoder);
	if (size < 0)
		return size;

	decoder->decoder.pos += size;

	return size;
}
