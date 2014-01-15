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

#include "pt_state.h"
#include "pt_packet_decode.h"

#include "pt_decode.h"
#include "pt_error.h"

#include <stdlib.h>
#include <string.h>


int pt_query_start(struct pt_decoder *decoder, uint64_t *addr)
{
	const uint8_t *pos;
	int status, errcode;

	if (!decoder)
		return -pte_invalid;

	pos = decoder->pos;
	if (!pos)
		return -pte_nosync;

	status = pt_fetch_decoder(decoder);
	if (status < 0)
		return status;

	/* We do need to start at a PSB in order to initialize the state. */
	if (decoder->next != &pt_decode_psb)
		return -pte_nosync;

	/* Read the header to initialize the state. */
	status = pt_read_header(decoder);
	if (status < 0)
		return status;

	/* Fill in the start address.
	 * We do this before reading ahead since the latter may read an
	 * adjacent PSB+ that might change the decoder's IP, causing us
	 * to skip code.
	 */
	if (addr) {
		status = pt_last_ip_query(addr, &decoder->ip);

		/* Make sure we don't clobber it later on. */
		if (!status)
			addr = NULL;
	}

	/* Read ahead until the first query-relevant packet.
	 * We ignore errors; they will be diagnosed in the first query.
	 */
	(void) pt_read_ahead(decoder);

	/* We return the current decoder status. */
	status = pt_status_flags(decoder);
	if (status < 0)
		return status;

	/* Tracing is enabled if and only if we have an IP after reading the
	 * PSB header.
	 */
	errcode = pt_last_ip_query(addr, &decoder->ip);
	if (!errcode)
		decoder->flags &= ~pdf_pt_disabled;
	else {
		decoder->flags |= pdf_pt_disabled;

		/* Indicate the missing IP in the status. */
		if (addr)
			status |= pts_ip_suppressed;
	}

	return status;
}

int pt_query_uncond_branch(struct pt_decoder *decoder, uint64_t *addr)
{
	int errcode, flags;

	if (!decoder || !addr)
		return -pte_invalid;

	errcode = pt_check_sync(decoder);
	if (errcode < 0)
		return errcode;

	flags = 0;
	for (;;) {
		const struct pt_decoder_function *dfun;
		int status;

		dfun = decoder->next;
		if (!dfun) {
			/* Repeat the decoder fetch to reproduce the error. */
			errcode = pt_fetch_decoder(decoder);

			/* We must get some error or something's wrong. */
			if (errcode >= 0)
				errcode = -pte_internal;

			return errcode;
		}

		if (!dfun->decode)
			return -pte_internal;

		/* Check for pending events. */
		status = pt_status_flags(decoder);
		if (status < 0)
			return status;

		/* There's an event ahead of us. */
		if (status & pts_event_pending)
			return -pte_bad_query;

		/* Clear the decoder's current event so we know when we
		 * accidentally skipped an event.
		 */
		decoder->event = NULL;

		/* We may see a single TNT packet if the current tnt is empty.
		 *
		 * If we see a TNT while the current tnt is not empty, it means
		 * that our user got out of sync. Let's report no data and hope
		 * that our user is able to re-sync.
		 */
		if ((dfun->flags & pdff_tnt) &&
		    !pt_tnt_cache_is_empty(&decoder->tnt))
			return -pte_bad_query;

		/* Apply the decoder function. */
		errcode = dfun->decode(decoder);
		if (errcode)
			return errcode;

		/* If we skipped an event, we're in trouble. */
		if (decoder->event)
			return -pte_nosync;

		/* We're done when we found a TIP packet that isn't part of an
		 * event.
		 */
		if (dfun->flags & pdff_tip) {
			uint64_t ip;

			/* We already decoded it, so the branch destination
			 * is stored in the decoder's last ip.
			 */
			errcode = pt_last_ip_query(&ip, &decoder->ip);
			if (errcode < 0)
				flags |= pts_ip_suppressed;
			else
				*addr = ip;

			break;
		}

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Read ahead until the next query-relevant packet. */
	(void) pt_read_ahead(decoder);

	flags |= pt_status_flags(decoder);

	return flags;
}

static int pt_cache_tnt(struct pt_decoder *decoder)
{
	int flags = 0;

	for (;;) {
		const struct pt_decoder_function *dfun;
		int errcode, status;

		dfun = decoder->next;
		if (!dfun) {
			/* Repeat the decoder fetch to reproduce the error. */
			errcode = pt_fetch_decoder(decoder);

			/* We must get some error or something's wrong. */
			if (errcode >= 0)
				errcode = -pte_internal;

			return errcode;
		}

		if (!dfun->decode)
			return -pte_internal;

		/* Check for pending events. */
		status = pt_status_flags(decoder);
		if (status < 0)
			return status;

		/* There's an event ahead of us. */
		if (status & pts_event_pending)
			return -pte_bad_query;

		/* Diagnose a TIP that has not been part of an event. */
		if (dfun->flags & pdff_tip)
			return -pte_bad_query;

		/* Clear the decoder's current event so we know when we
		 * accidentally skipped an event.
		 */
		decoder->event = NULL;

		/* Apply the decoder function. */
		errcode = dfun->decode(decoder);
		if (errcode)
			return errcode;

		/* If we skipped an event, we're in trouble. */
		if (decoder->event)
			return -pte_nosync;

		/* We're done when we decoded a TNT packet. */
		if (dfun->flags & pdff_tnt)
			break;

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Read ahead until the next query-relevant packet. */
	(void) pt_read_ahead(decoder);

	return flags;
}

int pt_query_cond_branch(struct pt_decoder *decoder, int *taken)
{
	int errcode, flags, query;

	if (!decoder || !taken)
		return -pte_invalid;

	errcode = pt_check_sync(decoder);
	if (errcode < 0)
		return errcode;

	/* We cache the latest tnt packet in the decoder. Let's re-fill the
	 * cache in case it is empty.
	 */
	flags = 0;
	if (pt_tnt_cache_is_empty(&decoder->tnt)) {
		errcode = pt_cache_tnt(decoder);
		if (errcode < 0)
			return errcode;

		flags |= errcode;
	}

	query = pt_tnt_cache_query(&decoder->tnt);
	if (query < 0)
		return query;

	*taken = query;

	flags |= pt_status_flags(decoder);

	return flags;
}

int pt_query_event(struct pt_decoder *decoder, struct pt_event *event)
{
	int errcode, flags;

	if (!decoder || !event)
		return -pte_invalid;

	errcode = pt_check_sync(decoder);
	if (errcode < 0)
		return errcode;

	flags = 0;
	for (;;) {
		const struct pt_decoder_function *dfun;
		int status;

		dfun = decoder->next;
		if (!dfun) {
			/* Repeat the decoder fetch to reproduce the error. */
			errcode = pt_fetch_decoder(decoder);

			/* We must get some error or something's wrong. */
			if (errcode >= 0)
				errcode = -pte_internal;

			return errcode;
		}

		if (!dfun->decode)
			return -pte_internal;

		/* Check for pending events. */
		status = pt_status_flags(decoder);
		if (status < 0)
			return status;

		/* Clear the decoder's current event so we know when decoding
		 * produces a new event.
		 */
		decoder->event = NULL;

		if (status & pts_event_pending) {
			/* Decode the event packet. */
			errcode = dfun->decode(decoder);
			if (errcode)
				return errcode;
		} else if (dfun->flags & pdff_tip) {
			/* We must not see a TIP packet.
			 *
			 * If we see one, it means that our user got out of
			 * sync. Let's report no data and hope that our user is
			 * able to re-sync.
			 */
			return -pte_bad_query;
		} else if ((dfun->flags & pdff_tnt) &&
			   !pt_tnt_cache_is_empty(&decoder->tnt)) {
			/* We may see a single TNT packet if the current tnt is
			 * empty.
			 *
			 * If we see a TNT while the current tnt is not empty,
			 * it means that our user got out of sync. Let's report
			 * no data and hope that our user is able to re-sync.
			 */
			return -pte_bad_query;
		} else {
			/* Apply any other decoder function. */
			errcode = dfun->decode(decoder);
			if (errcode)
				return errcode;
		}

		/* Check if there has been an event.
		 *
		 * Some packets may result in events in some but not in all
		 * configurations.
		 */
		if (decoder->event) {
			(void) memcpy(event, decoder->event, sizeof(*event));
			break;
		}

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Read ahead until the next query-relevant packet. */
	(void) pt_read_ahead(decoder);

	flags |= pt_status_flags(decoder);

	return flags;
}

uint64_t pt_query_time(struct pt_decoder *decoder)
{
	if (!decoder)
		return 0;

	return decoder->tsc;
}
