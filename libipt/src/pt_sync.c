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


/*
 * A psb packet contains a unique 2-byte repeating pattern.
 *
 * There are only two ways to fill up a 64bit work with such a pattern.
 */
const uint64_t psb_pattern[] = {
	((uint64_t) pt_psb_lohi		| (uint64_t) pt_psb_lohi << 16 |
	 (uint64_t) pt_psb_lohi << 32	| (uint64_t) pt_psb_lohi << 48),
	((uint64_t) pt_psb_hilo		| (uint64_t) pt_psb_hilo << 16 |
	 (uint64_t) pt_psb_hilo << 32	| (uint64_t) pt_psb_hilo << 48)
};

static const uint8_t *truncate(const uint8_t *pointer, size_t alignment)
{
	uintptr_t raw = (uintptr_t) pointer;

	raw /= alignment;
	raw *= alignment;

	return (const uint8_t *) raw;
}

static const uint8_t *align(const uint8_t *pointer, size_t alignment)
{
	return truncate(pointer + alignment - 1, alignment);
}

/* Find a psb packet given a position somewhere in the payload.
 *
 * Return the position of the psb packet.
 * Return NULL, if this is not a psb packet.
 */
static const uint8_t *pt_find_psb(const uint8_t *pos,
				  const uint8_t *begin, const uint8_t *end)
{
	/* Navigate to the end of the psb payload pattern.
	 *
	 * Beware that PSB is an extended opcode. We must not confuse the extend
	 * opcode of the following packet as belonging to the PSB.
	 */
	if (*pos != pt_psb_hi)
		pos++;

	for (; (pos + 1) < end; pos += 2) {
		uint8_t hi, lo;

		hi = pos[0];
		lo = pos[1];

		if (hi != pt_psb_hi)
			break;

		if (lo != pt_psb_lo)
			break;
	}
	/*
	 * We're right after the psb payload and within the buffer.
	 * Navigate to the expected beginning of the psb packet.
	 */
	pos -= (pt_psb_repeat_count * 2) + 2;

	/* Check if we're still inside the buffer. */
	if (pos < begin)
		return NULL;

	/* Check that this is indeed a psb packet we're at. */
	if (pos[0] != pt_opc_psb)
		return NULL;
	if (pos[1] != pt_ext_psb)
		return NULL;

	return pos;
}

/* Sync the decoder at the given position.
 *
 * Returns zero on success.
 * Returns a negative error code otherwise.
 */
static int pt_sync_decoder(struct pt_decoder *decoder, const uint8_t *pos)
{
	struct pt_packet packet;
	int status;

	decoder->pos = pos;

	/* Let's try to decode the PSB packet we found. */
	status = pt_decode_psb.packet(&packet, decoder);
	if (status < 0)
		return -pte_nosync;

	/* We synchronized successfully. */
	decoder->sync = pos;
	decoder->pos = pos;

	pt_reset(decoder);

	return 0;
}

/* Synchronize the decoder.
 */

int pt_sync_forward(struct pt_decoder *decoder)
{
	const uint8_t *pos, *begin, *end, *sync;

	if (!decoder)
		return -pte_invalid;

	begin = pt_begin(decoder);
	end = pt_end(decoder);

	sync = decoder->sync;
	pos = decoder->pos;
	if (!pos)
		pos = begin;

	/* Check if the buffer is valid. */
	if ((pos < begin) || (end < pos))
		return -pte_invalid;

	/* Ignore the current syncpoint. */
	if (pos == sync)
		pos += ptps_psb;

	/* We search for a full 64bit word. It's OK to skip the current one. */
	pos = align(pos, sizeof(*psb_pattern));

	/* Search for the psb payload pattern in the buffer. */
	for (;;) {
		const uint8_t *current = pos;
		uint64_t val;

		pos += sizeof(uint64_t);
		if (end < pos)
			return -pte_eos;

		val = * (const uint64_t *) current;

		if ((val != psb_pattern[0]) && (val != psb_pattern[1]))
			continue;

		/* We found a 64bit word's worth of psb payload pattern. */
		current = pt_find_psb(pos, begin, end);
		if (current) {
			int errcode;

			errcode = pt_sync_decoder(decoder, current);
			if (!errcode)
				return 0;
		}
	}
}

int pt_sync_backward(struct pt_decoder *decoder)
{
	const uint8_t *sync, *pos, *begin, *end;

	if (!decoder)
		return -pte_invalid;

	begin = pt_begin(decoder);
	end = pt_end(decoder);

	sync = decoder->sync;
	pos = decoder->pos;
	if (!pos)
		pos = end;

	/* Check if we're still inside the buffer. */
	if ((pos < begin) || (end < pos))
		return -pte_invalid;

	/* We search for a full 64bit word. It's OK to skip the current one. */
	pos = truncate(pos, sizeof(*psb_pattern));

	/* Search for the psb payload pattern in the buffer. */
	for (;;) {
		const uint8_t *next = pos;
		uint64_t val;

		pos -= sizeof(uint64_t);
		if (pos < begin)
			return -pte_eos;

		val = * (const uint64_t *) pos;

		if ((val != psb_pattern[0]) && (val != psb_pattern[1]))
			continue;

		/* We found a 64bit word's worth of psb payload pattern. */
		next = pt_find_psb(next, begin, end);

		/* Make sure we skip the current segment. */
		if (next && (!sync || (next < sync))) {
			int errcode;

			errcode = pt_sync_decoder(decoder, next);
			if (!errcode)
				return 0;
		}
	}
}
