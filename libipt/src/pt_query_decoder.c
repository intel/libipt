/*
 * Copyright (c) 2014-2017, Intel Corporation
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

#include "pt_query_decoder.h"
#include "pt_sync.h"
#include "pt_decoder_function.h"
#include "pt_packet.h"
#include "pt_packet_decoder.h"
#include "pt_config.h"
#include "pt_opcodes.h"

#include "intel-pt.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>


/* Find a FUP in a PSB+ header.
 *
 * The packet @decoder must be synchronized onto the trace stream at the
 * beginning or somewhere inside a PSB+ header.
 *
 * It uses @packet to hold trace packets during its search.  If the search is
 * successful, @packet will contain the first (and hopefully only) FUP packet in
 * this PSB+.  Otherwise, @packet may contain anything.
 *
 * Returns one if a FUP packet is found (@packet will contain it).
 * Returns zero if no FUP packet is found (@packet is undefined).
 * Returns a negative error code otherwise.
 */
static int pt_qry_find_header_fup(struct pt_packet *packet,
				  struct pt_packet_decoder *decoder)
{
	if (!packet || !decoder)
		return -pte_internal;

	for (;;) {
		int errcode;

		errcode = pt_pkt_next(decoder, packet, sizeof(*packet));
		if (errcode < 0)
			return errcode;

		switch (packet->type) {
		default:
			/* Ignore the packet. */
			break;

		case ppt_psbend:
			/* There's no FUP in here. */
			return 0;

		case ppt_fup:
			/* Found it. */
			return 1;
		}
	}
}

int pt_qry_decoder_init(struct pt_query_decoder *decoder,
			const struct pt_config *config)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	memset(decoder, 0, sizeof(*decoder));

	errcode = pt_config_from_user(&decoder->config, config);
	if (errcode < 0)
		return errcode;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->time);
	pt_time_init(&decoder->last_time);
	pt_tcal_init(&decoder->tcal);
	pt_evq_init(&decoder->evq);

	return 0;
}

struct pt_query_decoder *pt_qry_alloc_decoder(const struct pt_config *config)
{
	struct pt_query_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_qry_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_qry_decoder_fini(struct pt_query_decoder *decoder)
{
	(void) decoder;

	/* Nothing to do. */
}

void pt_qry_free_decoder(struct pt_query_decoder *decoder)
{
	pt_qry_decoder_fini(decoder);
	free(decoder);
}

static void pt_qry_reset(struct pt_query_decoder *decoder)
{
	if (!decoder)
		return;

	decoder->enabled = 0;
	decoder->consume_packet = 0;
	decoder->event = NULL;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->time);
	pt_time_init(&decoder->last_time);
	pt_tcal_init(&decoder->tcal);
	pt_evq_init(&decoder->evq);
}

static int pt_qry_will_event(const struct pt_query_decoder *decoder)
{
	const struct pt_decoder_function *dfun;

	if (!decoder)
		return -pte_internal;

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

static int pt_qry_will_eos(const struct pt_query_decoder *decoder)
{
	const struct pt_decoder_function *dfun;
	int errcode;

	if (!decoder)
		return -pte_internal;

	dfun = decoder->next;
	if (dfun)
		return 0;

	/* The decoding function may be NULL for two reasons:
	 *
	 *   - we ran out of trace
	 *   - we ran into a fetch error such as -pte_bad_opc
	 *
	 * Let's fetch again.
	 */
	errcode = pt_df_fetch(&dfun, decoder->pos, &decoder->config);
	return errcode == -pte_eos;
}

static int pt_qry_status_flags(const struct pt_query_decoder *decoder)
{
	int flags = 0;

	if (!decoder)
		return -pte_internal;

	/* Some packets force out TNT and any deferred TIPs in order to
	 * establish the correct context for the subsequent packet.
	 *
	 * Users are expected to first navigate to the correct code region
	 * by using up the cached TNT bits before interpreting any subsequent
	 * packets.
	 *
	 * We do need to read ahead in order to signal upcoming events.  We may
	 * have already decoded those packets while our user has not navigated
	 * to the correct code region, yet.
	 *
	 * In order to have our user use up the cached TNT bits first, we do
	 * not indicate the next event until the TNT cache is empty.
	 */
	if (pt_tnt_cache_is_empty(&decoder->tnt)) {
		if (pt_qry_will_event(decoder))
			flags |= pts_event_pending;

		if (pt_qry_will_eos(decoder))
			flags |= pts_eos;
	}

	return flags;
}

static int pt_qry_provoke_fetch_error(const struct pt_query_decoder *decoder)
{
	const struct pt_decoder_function *dfun;
	int errcode;

	if (!decoder)
		return -pte_internal;

	/* Repeat the decoder fetch to reproduce the error. */
	errcode = pt_df_fetch(&dfun, decoder->pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* We must get some error or something's wrong. */
	return -pte_internal;
}

static int pt_qry_read_ahead(struct pt_query_decoder *decoder)
{
	for (;;) {
		const struct pt_decoder_function *dfun;
		int errcode;

		errcode = pt_df_fetch(&decoder->next, decoder->pos,
				      &decoder->config);
		if (errcode)
			return errcode;

		dfun = decoder->next;
		if (!dfun)
			return -pte_internal;

		if (!dfun->decode)
			return -pte_internal;

		/* We're done once we reach
		 *
		 * - a branching related packet. */
		if (dfun->flags & (pdff_tip | pdff_tnt))
			return 0;

		/* - an event related packet. */
		if (pt_qry_will_event(decoder))
			return 0;

		/* Decode status update packets. */
		errcode = dfun->decode(decoder);
		if (errcode)
			return errcode;
	}
}

static int pt_qry_start(struct pt_query_decoder *decoder, const uint8_t *pos,
			uint64_t *addr)
{
	const struct pt_decoder_function *dfun;
	int status, errcode;

	if (!decoder || !pos)
		return -pte_invalid;

	pt_qry_reset(decoder);

	decoder->sync = pos;
	decoder->pos = pos;

	errcode = pt_df_fetch(&decoder->next, pos, &decoder->config);
	if (errcode)
		return errcode;

	dfun = decoder->next;

	/* We do need to start at a PSB in order to initialize the state. */
	if (dfun != &pt_decode_psb)
		return -pte_nosync;

	/* Decode the PSB+ header to initialize the state. */
	errcode = dfun->decode(decoder);
	if (errcode < 0)
		return errcode;

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

	/* Read ahead until the first query-relevant packet. */
	errcode = pt_qry_read_ahead(decoder);
	if (errcode < 0)
		return errcode;

	/* We return the current decoder status. */
	status = pt_qry_status_flags(decoder);
	if (status < 0)
		return status;

	errcode = pt_last_ip_query(addr, &decoder->ip);
	if (errcode < 0) {
		/* Indicate the missing IP in the status. */
		if (addr)
			status |= pts_ip_suppressed;
	}

	return status;
}

static int pt_qry_apply_tsc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_tsc *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_update_tsc(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tsc(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_header_tsc(struct pt_time *time,
				   struct pt_time_cal *tcal,
				   const struct pt_packet_tsc *packet,
				   const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_header_tsc(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tsc(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_cbr(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_cbr *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_update_cbr(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_cbr(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_header_cbr(struct pt_time *time,
				   struct pt_time_cal *tcal,
				   const struct pt_packet_cbr *packet,
				   const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_header_cbr(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_cbr(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_tma(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_tma *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_update_tma(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tma(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_mtc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_mtc *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_update_mtc(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_mtc(time, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_qry_apply_cyc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_cyc *packet,
			    const struct pt_config *config)
{
	uint64_t fcr;
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 *
	 * We currently do not track them.
	 */
	errcode = pt_tcal_update_cyc(tcal, packet, config);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	/* We need the FastCounter to Cycles ratio below.  Fall back to
	 * an invalid ratio of 0 if calibration has not kicked in, yet.
	 *
	 * This will be tracked as packet loss in struct pt_time.
	 */
	errcode = pt_tcal_fcr(&fcr, tcal);
	if (errcode < 0) {
		if (errcode == -pte_no_time)
			fcr = 0ull;
		else
			return errcode;
	}

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_cyc(time, packet, config, fcr);
	if (errcode < 0 && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

int pt_qry_sync_forward(struct pt_query_decoder *decoder, uint64_t *ip)
{
	const uint8_t *pos, *sync;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	sync = decoder->sync;
	pos = decoder->pos;
	if (!pos)
		pos = decoder->config.begin;

	if (pos == sync)
		pos += ptps_psb;

	errcode = pt_sync_forward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	return pt_qry_start(decoder, sync, ip);
}

int pt_qry_sync_backward(struct pt_query_decoder *decoder, uint64_t *ip)
{
	const uint8_t *start, *sync;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	start = decoder->pos;
	if (!start)
		start = decoder->config.end;

	sync = start;
	for (;;) {
		errcode = pt_sync_backward(&sync, sync, &decoder->config);
		if (errcode < 0)
			return errcode;

		errcode = pt_qry_start(decoder, sync, ip);
		if (errcode < 0) {
			/* Ignore incomplete trace segments at the end.  We need
			 * a full PSB+ to start decoding.
			 */
			if (errcode == -pte_eos)
				continue;

			return errcode;
		}

		/* An empty trace segment in the middle of the trace might bring
		 * us back to where we started.
		 *
		 * We're done when we reached a new position.
		 */
		if (decoder->pos != start)
			break;
	}

	return 0;
}

int pt_qry_sync_set(struct pt_query_decoder *decoder, uint64_t *ip,
		    uint64_t offset)
{
	const uint8_t *sync, *pos;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	pos = decoder->config.begin + offset;

	errcode = pt_sync_set(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	return pt_qry_start(decoder, sync, ip);
}

int pt_qry_get_offset(const struct pt_query_decoder *decoder, uint64_t *offset)
{
	const uint8_t *begin, *pos;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = decoder->config.begin;
	pos = decoder->pos;

	if (!pos)
		return -pte_nosync;

	*offset = pos - begin;
	return 0;
}

int pt_qry_get_sync_offset(const struct pt_query_decoder *decoder,
			   uint64_t *offset)
{
	const uint8_t *begin, *sync;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = decoder->config.begin;
	sync = decoder->sync;

	if (!sync)
		return -pte_nosync;

	*offset = sync - begin;
	return 0;
}

const struct pt_config *
pt_qry_get_config(const struct pt_query_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return &decoder->config;
}

static int pt_qry_cache_tnt(struct pt_query_decoder *decoder)
{
	int errcode;

	for (;;) {
		const struct pt_decoder_function *dfun;

		dfun = decoder->next;
		if (!dfun)
			return pt_qry_provoke_fetch_error(decoder);

		if (!dfun->decode)
			return -pte_internal;

		/* There's an event ahead of us. */
		if (pt_qry_will_event(decoder))
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
			return -pte_event_ignored;

		/* We're done when we decoded a TNT packet. */
		if (dfun->flags & pdff_tnt)
			break;

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_qry_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Preserve the time at the TNT packet. */
	decoder->last_time = decoder->time;

	/* Read ahead until the next query-relevant packet. */
	errcode = pt_qry_read_ahead(decoder);
	if ((errcode < 0) && (errcode != -pte_eos))
		return errcode;

	return 0;
}

int pt_qry_cond_branch(struct pt_query_decoder *decoder, int *taken)
{
	int errcode, query;

	if (!decoder || !taken)
		return -pte_invalid;

	/* We cache the latest tnt packet in the decoder. Let's re-fill the
	 * cache in case it is empty.
	 */
	if (pt_tnt_cache_is_empty(&decoder->tnt)) {
		errcode = pt_qry_cache_tnt(decoder);
		if (errcode < 0)
			return errcode;
	}

	query = pt_tnt_cache_query(&decoder->tnt);
	if (query < 0)
		return query;

	*taken = query;

	return pt_qry_status_flags(decoder);
}

int pt_qry_indirect_branch(struct pt_query_decoder *decoder, uint64_t *addr)
{
	int errcode, flags;

	if (!decoder || !addr)
		return -pte_invalid;

	flags = 0;
	for (;;) {
		const struct pt_decoder_function *dfun;

		dfun = decoder->next;
		if (!dfun)
			return pt_qry_provoke_fetch_error(decoder);

		if (!dfun->decode)
			return -pte_internal;

		/* There's an event ahead of us. */
		if (pt_qry_will_event(decoder))
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
			return -pte_event_ignored;

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
		errcode = pt_qry_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Preserve the time at the TIP packet. */
	decoder->last_time = decoder->time;

	/* Read ahead until the next query-relevant packet. */
	errcode = pt_qry_read_ahead(decoder);
	if ((errcode < 0) && (errcode != -pte_eos))
		return errcode;

	flags |= pt_qry_status_flags(decoder);

	return flags;
}

int pt_qry_event(struct pt_query_decoder *decoder, struct pt_event *event,
		 size_t size)
{
	int errcode, flags;

	if (!decoder || !event)
		return -pte_invalid;

	if (size < offsetof(struct pt_event, variant))
		return -pte_invalid;

	/* We do not allow querying for events while there are still TNT
	 * bits to consume.
	 */
	if (!pt_tnt_cache_is_empty(&decoder->tnt))
		return -pte_bad_query;

	/* Do not provide more than we actually have. */
	if (sizeof(*event) < size)
		size = sizeof(*event);

	flags = 0;
	for (;;) {
		const struct pt_decoder_function *dfun;

		dfun = decoder->next;
		if (!dfun)
			return pt_qry_provoke_fetch_error(decoder);

		if (!dfun->decode)
			return -pte_internal;

		/* We must not see a TIP or TNT packet unless it belongs
		 * to an event.
		 *
		 * If we see one, it means that our user got out of sync.
		 * Let's report no data and hope that our user is able
		 * to re-sync.
		 */
		if ((dfun->flags & (pdff_tip | pdff_tnt)) &&
		    !pt_qry_will_event(decoder))
			return -pte_bad_query;

		/* Clear the decoder's current event so we know when decoding
		 * produces a new event.
		 */
		decoder->event = NULL;

		/* Apply any other decoder function. */
		errcode = dfun->decode(decoder);
		if (errcode)
			return errcode;

		/* Check if there has been an event.
		 *
		 * Some packets may result in events in some but not in all
		 * configurations.
		 */
		if (decoder->event) {
			(void) memcpy(event, decoder->event, size);
			break;
		}

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_qry_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Preserve the time at the event. */
	decoder->last_time = decoder->time;

	/* Read ahead until the next query-relevant packet. */
	errcode = pt_qry_read_ahead(decoder);
	if ((errcode < 0) && (errcode != -pte_eos))
		return errcode;

	flags |= pt_qry_status_flags(decoder);

	return flags;
}

int pt_qry_time(struct pt_query_decoder *decoder, uint64_t *time,
		uint32_t *lost_mtc, uint32_t *lost_cyc)
{
	if (!decoder || !time)
		return -pte_invalid;

	return pt_time_query_tsc(time, lost_mtc, lost_cyc, &decoder->last_time);
}

int pt_qry_core_bus_ratio(struct pt_query_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	return pt_time_query_cbr(cbr, &decoder->last_time);
}

static void pt_qry_add_event_time(struct pt_event *event,
				  const struct pt_query_decoder *decoder)
{
	int errcode;

	if (!event || !decoder)
		return;

	errcode = pt_time_query_tsc(&event->tsc, &event->lost_mtc,
				    &event->lost_cyc, &decoder->time);
	if (errcode >= 0)
		event->has_tsc = 1;
}

int pt_qry_decode_unknown(struct pt_query_decoder *decoder)
{
	struct pt_packet packet;
	int size;

	size = pt_pkt_read_unknown(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_pad(struct pt_query_decoder *decoder)
{
	decoder->pos += ptps_pad;

	return 0;
}

static int pt_qry_read_psb_header(struct pt_query_decoder *decoder)
{
	pt_last_ip_init(&decoder->ip);

	for (;;) {
		const struct pt_decoder_function *dfun;
		int errcode;

		errcode = pt_df_fetch(&decoder->next, decoder->pos,
				      &decoder->config);
		if (errcode)
			return errcode;

		dfun = decoder->next;
		if (!dfun)
			return -pte_internal;

		/* We're done once we reach an psbend packet. */
		if (dfun->flags & pdff_psbend)
			return 0;

		if (!dfun->header)
			return -pte_bad_context;

		errcode = dfun->header(decoder);
		if (errcode)
			return errcode;
	}
}

int pt_qry_decode_psb(struct pt_query_decoder *decoder)
{
	const uint8_t *pos;
	int size, errcode;

	pos = decoder->pos;

	size = pt_pkt_read_psb(pos, &decoder->config);
	if (size < 0)
		return size;

	decoder->pos += size;

	errcode = pt_qry_read_psb_header(decoder);
	if (errcode < 0) {
		/* Move back to the PSB so we have a chance to recover and
		 * continue decoding.
		 */
		decoder->pos = pos;

		/* Clear any PSB+ events that have already been queued. */
		(void) pt_evq_clear(&decoder->evq, evb_psbend);

		/* Reset the decoder's decode function. */
		decoder->next = &pt_decode_psb;

		return errcode;
	}

	/* The next packet following the PSB header will be of type PSBEND.
	 *
	 * Decoding this packet will publish the PSB events what have been
	 * accumulated while reading the PSB header.
	 */
	return 0;
}

static void pt_qry_add_event_ip(struct pt_event *event, uint64_t *ip,
				const struct pt_query_decoder *decoder)
{
	int errcode;

	errcode = pt_last_ip_query(ip, &decoder->ip);
	if (errcode < 0)
		event->ip_suppressed = 1;
}

/* Decode a generic IP packet.
 *
 * Returns the number of bytes read, on success.
 * Returns -pte_eos if the ip does not fit into the buffer.
 * Returns -pte_bad_packet if the ip compression is not known.
 */
static int pt_qry_decode_ip(struct pt_query_decoder *decoder)
{
	struct pt_packet_ip packet;
	int errcode, size;

	size = pt_pkt_read_ip(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_last_ip_update_ip(&decoder->ip, &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* We do not update the decoder's position, yet. */

	return size;
}

static int pt_qry_consume_tip(struct pt_query_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = pt_qry_decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to TIP. */
	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	if (ev) {
		switch (ev->type) {
		default:
			return -pte_internal;

		case ptev_async_branch:
			pt_qry_add_event_ip(ev, &ev->variant.async_branch.to,
					    decoder);

			decoder->consume_packet = 1;

			break;

		case ptev_async_paging:
			pt_qry_add_event_ip(ev, &ev->variant.async_paging.ip,
					    decoder);
			break;

		case ptev_async_vmcs:
			pt_qry_add_event_ip(ev, &ev->variant.async_vmcs.ip,
					    decoder);
			break;

		case ptev_exec_mode:
			pt_qry_add_event_ip(ev, &ev->variant.exec_mode.ip,
					    decoder);
			break;
		}

		/* Publish the event. */
		decoder->event = ev;

		/* Process further pending events. */
		if (pt_evq_pending(&decoder->evq, evb_tip))
			return 0;

		/* No further events.
		 *
		 * If none of the events consumed the packet, we're done.
		 */
		if (!decoder->consume_packet)
			return 0;

		/* We're done with this packet. Clear the flag we set previously
		 * and consume it.
		 */
		decoder->consume_packet = 0;
	}

	return pt_qry_consume_tip(decoder, size);
}

int pt_qry_decode_tnt_8(struct pt_query_decoder *decoder)
{
	struct pt_packet_tnt packet;
	int size, errcode;

	size = pt_pkt_read_tnt_8(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_tnt_cache_update_tnt(&decoder->tnt, &packet,
					  &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tnt_64(struct pt_query_decoder *decoder)
{
	struct pt_packet_tnt packet;
	int size, errcode;

	size = pt_pkt_read_tnt_64(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_tnt_cache_update_tnt(&decoder->tnt, &packet,
					  &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

static int pt_qry_consume_tip_pge(struct pt_query_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip_pge(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = pt_qry_decode_ip(decoder);
	if (size < 0)
		return size;

	/* We send the enable event first. This is more convenient for our users
	 * and does not require them to either store or blindly apply other
	 * events that might be pending.
	 *
	 * We use the consume packet decoder flag to indicate this.
	 */
	if (!decoder->consume_packet) {
		uint64_t ip;
		int errcode;

		/* We can't afford a suppressed IP, here. */
		errcode = pt_last_ip_query(&ip, &decoder->ip);
		if (errcode < 0)
			return -pte_bad_packet;

		/* This packet signals a standalone enabled event. */
		ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;
		ev->type = ptev_enabled;
		ev->variant.enabled.ip = ip;

		pt_qry_add_event_time(ev, decoder);

		/* Discard any cached TNT bits.
		 *
		 * They should have been consumed at the corresponding disable
		 * event. If they have not, for whatever reason, discard them
		 * now so our user does not get out of sync.
		 */
		pt_tnt_cache_init(&decoder->tnt);

		/* Process pending events next. */
		decoder->consume_packet = 1;
		decoder->enabled = 1;
	} else {
		/* Process any pending events binding to TIP. */
		ev = pt_evq_dequeue(&decoder->evq, evb_tip);
		if (ev) {
			switch (ev->type) {
			default:
				return -pte_internal;

			case ptev_exec_mode:
				pt_qry_add_event_ip(ev,
						    &ev->variant.exec_mode.ip,
						    decoder);
				break;
			}
		}
	}

	/* We must have an event. Either the initial enable event or one of the
	 * queued events.
	 */
	if (!ev)
		return -pte_internal;

	/* Publish the event. */
	decoder->event = ev;

	/* Process further pending events. */
	if (pt_evq_pending(&decoder->evq, evb_tip))
		return 0;

	/* We must consume the packet. */
	if (!decoder->consume_packet)
		return -pte_internal;

	decoder->consume_packet = 0;

	return pt_qry_consume_tip_pge(decoder, size);
}

static int pt_qry_consume_tip_pgd(struct pt_query_decoder *decoder, int size)
{
	decoder->enabled = 0;
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip_pgd(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	uint64_t at;
	int size;

	size = pt_qry_decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to TIP. */
	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	if (ev) {
		/* The only event we expect is an async branch. */
		if (ev->type != ptev_async_branch)
			return -pte_internal;

		/* We do not expect any further events. */
		if (pt_evq_pending(&decoder->evq, evb_tip))
			return -pte_internal;

		/* Turn the async branch into an async disable. */
		at = ev->variant.async_branch.from;

		ev->type = ptev_async_disabled;
		ev->variant.async_disabled.at = at;
		pt_qry_add_event_ip(ev, &ev->variant.async_disabled.ip,
				    decoder);
	} else {
		/* This packet signals a standalone disabled event. */
		ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;
		ev->type = ptev_disabled;
		pt_qry_add_event_ip(ev, &ev->variant.disabled.ip, decoder);
		pt_qry_add_event_time(ev, decoder);
	}

	/* Publish the event. */
	decoder->event = ev;

	return pt_qry_consume_tip_pgd(decoder, size);
}

static int pt_qry_consume_fup(struct pt_query_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

static int scan_for_erratum_bdm70(struct pt_packet_decoder *decoder)
{
	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (errcode < 0) {
			/* Running out of packets is not an error. */
			if (errcode == -pte_eos)
				errcode = 0;

			return errcode;
		}

		switch (packet.type) {
		default:
			/* All other packets cancel our search.
			 *
			 * We do not enumerate those packets since we also
			 * want to include new packets.
			 */
			return 0;

		case ppt_tip_pge:
			/* We found it - the erratum applies. */
			return 1;

		case ppt_pad:
		case ppt_tsc:
		case ppt_cbr:
		case ppt_psbend:
		case ppt_pip:
		case ppt_mode:
		case ppt_vmcs:
		case ppt_tma:
		case ppt_mtc:
		case ppt_cyc:
		case ppt_mnt:
			/* Intentionally skip a few packets. */
			continue;
		}
	}
}

static int check_erratum_bdm70(const uint8_t *pos,
			       const struct pt_config *config)
{
	struct pt_packet_decoder decoder;
	int errcode;

	if (!pos || !config)
		return -pte_internal;

	errcode = pt_pkt_decoder_init(&decoder, config);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_set(&decoder, (uint64_t) (pos - config->begin));
	if (errcode >= 0)
		errcode = scan_for_erratum_bdm70(&decoder);

	pt_pkt_decoder_fini(&decoder);
	return errcode;
}

int pt_qry_header_fup(struct pt_query_decoder *decoder)
{
	struct pt_packet_ip packet;
	int errcode, size;

	size = pt_pkt_read_ip(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	if (decoder->config.errata.bdm70 && !decoder->enabled) {
		errcode = check_erratum_bdm70(decoder->pos + size,
					      &decoder->config);
		if (errcode < 0)
			return errcode;

		if (errcode)
			return pt_qry_consume_fup(decoder, size);
	}

	errcode = pt_last_ip_update_ip(&decoder->ip, &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* Tracing is enabled if we have an IP in the header. */
	if (packet.ipc != pt_ipc_suppressed)
		decoder->enabled = 1;

	return pt_qry_consume_fup(decoder, size);
}

int pt_qry_decode_fup(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = pt_qry_decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to FUP. */
	ev = pt_evq_dequeue(&decoder->evq, evb_fup);
	if (ev) {
		switch (ev->type) {
		default:
			return -pte_internal;

		case ptev_overflow: {
			uint64_t ip;
			int errcode;

			/* We can't afford a suppressed IP, here. */
			errcode = pt_last_ip_query(&ip, &decoder->ip);
			if (errcode < 0)
				return -pte_bad_packet;

			ev->variant.overflow.ip = ip;

			decoder->consume_packet = 1;
		}
			break;

		case ptev_tsx:
			pt_qry_add_event_ip(ev, &ev->variant.tsx.ip, decoder);

			if (!(ev->variant.tsx.aborted))
				decoder->consume_packet = 1;

			break;

		case ptev_exstop:
			pt_qry_add_event_ip(ev, &ev->variant.exstop.ip,
					    decoder);

			decoder->consume_packet = 1;
			break;

		case ptev_mwait:
			pt_qry_add_event_ip(ev, &ev->variant.mwait.ip, decoder);

			decoder->consume_packet = 1;
			break;

		case ptev_ptwrite:
			pt_qry_add_event_ip(ev, &ev->variant.ptwrite.ip,
					    decoder);

			decoder->consume_packet = 1;
			break;
		}

		/* Publish the event. */
		decoder->event = ev;

		/* Process further pending events. */
		if (pt_evq_pending(&decoder->evq, evb_fup))
			return 0;

		/* No further events.
		 *
		 * If none of the events consumed the packet, we're done.
		 */
		if (!decoder->consume_packet)
			return 0;

		/* We're done with this packet. Clear the flag we set previously
		 * and consume it.
		 */
		decoder->consume_packet = 0;
	} else {
		/* FUP indicates an async branch event; it binds to TIP.
		 *
		 * We do need an IP in this case.
		 */
		uint64_t ip;
		int errcode;

		errcode = pt_last_ip_query(&ip, &decoder->ip);
		if (errcode < 0)
			return -pte_bad_packet;

		ev = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_async_branch;
		ev->variant.async_branch.from = ip;

		pt_qry_add_event_time(ev, decoder);
	}

	return pt_qry_consume_fup(decoder, size);
}

int pt_qry_decode_pip(struct pt_query_decoder *decoder)
{
	struct pt_packet_pip packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_pip(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* Paging events are either standalone or bind to the same TIP packet
	 * as an in-flight async branch event.
	 */
	event = pt_evq_find(&decoder->evq, evb_tip, ptev_async_branch);
	if (!event) {
		event = pt_evq_standalone(&decoder->evq);
		if (!event)
			return -pte_internal;
		event->type = ptev_paging;
		event->variant.paging.cr3 = packet.cr3;
		event->variant.paging.non_root = packet.nr;

		pt_qry_add_event_time(event, decoder);

		decoder->event = event;
	} else {
		event = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!event)
			return -pte_nomem;

		event->type = ptev_async_paging;
		event->variant.async_paging.cr3 = packet.cr3;
		event->variant.async_paging.non_root = packet.nr;

		pt_qry_add_event_time(event, decoder);
	}

	decoder->pos += size;
	return 0;
}

int pt_qry_header_pip(struct pt_query_decoder *decoder)
{
	struct pt_packet_pip packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_pip(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* Paging events are reported at the end of the PSB. */
	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!event)
		return -pte_nomem;

	event->type = ptev_async_paging;
	event->variant.async_paging.cr3 = packet.cr3;
	event->variant.async_paging.non_root = packet.nr;

	decoder->pos += size;
	return 0;
}

static int pt_qry_process_pending_psb_events(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;

	ev = pt_evq_dequeue(&decoder->evq, evb_psbend);
	if (!ev)
		return 0;

	pt_qry_add_event_time(ev, decoder);

	/* PSB+ events are status updates. */
	ev->status_update = 1;

	/* Publish the event. */
	decoder->event = ev;

	switch (ev->type) {
	default:
		return -pte_internal;

	case ptev_async_paging:
		pt_qry_add_event_ip(ev, &ev->variant.async_paging.ip, decoder);
		break;

	case ptev_exec_mode:
		pt_qry_add_event_ip(ev, &ev->variant.exec_mode.ip, decoder);
		break;

	case ptev_tsx:
		pt_qry_add_event_ip(ev, &ev->variant.tsx.ip, decoder);
		break;

	case ptev_async_vmcs:
		pt_qry_add_event_ip(ev, &ev->variant.async_vmcs.ip, decoder);
		break;

	case ptev_cbr:
		break;

	case ptev_mnt:
		/* Maintenance packets may appear anywhere.  Do not mark them as
		 * status updates even if they appear in PSB+.
		 */
		ev->status_update = 0;
		break;
	}

	/* Signal a pending event. */
	return 1;
}

/* Recover from SKD010.
 *
 * Creates and publishes an overflow event at @packet's IP payload.
 *
 * Further updates @decoder as follows:
 *
 *   - set time tracking to @time and @tcal
 *   - set the position to @offset
 *   - set ip to @packet's IP payload
 *   - set tracing to be enabled
 *
 * Returns 1 on success, a negative error code otherwise.
 */
static int skd010_recover(struct pt_query_decoder *decoder,
			  const struct pt_packet_ip *packet,
			  const struct pt_time_cal *tcal,
			  const struct pt_time *time, uint64_t offset)
{
	struct pt_last_ip ip;
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet || !tcal || !time)
		return -pte_internal;

	/* We use the decoder's IP.  It should be newly initialized. */
	ip = decoder->ip;

	/* Extract the IP payload from the packet. */
	errcode = pt_last_ip_update_ip(&ip, packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* Synthesize the overflow event. */
	ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;

	/* We do need a full IP. */
	errcode = pt_last_ip_query(&ev->variant.overflow.ip, &ip);
	if (errcode < 0)
		return -pte_bad_context;

	/* We continue decoding at the given offset. */
	decoder->pos = decoder->config.begin + offset;

	/* Tracing is enabled. */
	decoder->enabled = 1;
	decoder->ip = ip;

	decoder->time = *time;
	decoder->tcal = *tcal;

	/* After updating the decoder's time, we can fill in the event
	 * timestamp.
	 */
	pt_qry_add_event_time(ev, decoder);

	/* Publish the event. */
	decoder->event = ev;
	return 1;
}

/* Recover from SKD010 with tracing disabled.
 *
 * Creates and publishes a standalone overflow event.
 *
 * Further updates @decoder as follows:
 *
 *   - set time tracking to @time and @tcal
 *   - set the position to @offset
 *   - set tracing to be disabled
 *
 * Returns 1 on success, a negative error code otherwise.
 */
static int skd010_recover_disabled(struct pt_query_decoder *decoder,
				   const struct pt_time_cal *tcal,
				   const struct pt_time *time, uint64_t offset)
{
	struct pt_event *ev;

	if (!decoder || !tcal || !time)
		return -pte_internal;

	/* Synthesize the overflow event. */
	ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;

	/* We suppress the IP to indicate that tracing has been
	 * disabled before the overflow resolved.  There can be
	 * several events before tracing is enabled again.
	 */
	ev->ip_suppressed = 1;

	/* We continue decoding at the given offset. */
	decoder->pos = decoder->config.begin + offset;

	/* Tracing is disabled. */
	decoder->enabled = 0;

	decoder->time = *time;
	decoder->tcal = *tcal;

	/* After updating the decoder's time, we can fill in the event
	 * timestamp.
	 */
	pt_qry_add_event_time(ev, decoder);

	/* Publish the event. */
	decoder->event = ev;

	return 1;
}

/* Scan ahead for a packet at which to resume after an overflow.
 *
 * This function is called after an OVF without a corresponding FUP.  This
 * normally means that the overflow resolved while tracing was disabled.
 *
 * With erratum SKD010 it might also mean that the FUP (or TIP.PGE) was dropped.
 * The overflow thus resolved while tracing was enabled (or tracing was enabled
 * after the overflow resolved).  Search for an indication whether tracing is
 * enabled or disabled by scanning upcoming packets.
 *
 * If we can confirm that tracing is disabled, the erratum does not apply and we
 * can continue normally.
 *
 * If we can confirm that tracing is enabled, the erratum applies and we try to
 * recover by synchronizing at a later packet and a different IP.  If we can't
 * recover, pretend the erratum didn't apply so we run into the error later.
 * Since this assumes that tracing is disabled, no harm should be done, i.e. no
 * bad trace should be generated.
 *
 * Returns a positive value if the overflow is handled.
 * Returns zero if the overflow is not yet handled.
 * Returns a negative error code otherwise.
 */
static int skd010_scan_for_ovf_resume(struct pt_packet_decoder *pkt,
				      struct pt_query_decoder *decoder)
{
	struct pt_time_cal tcal;
	struct pt_time time;
	struct {
		struct pt_time_cal tcal;
		struct pt_time time;
		uint64_t offset;
	} mode_tsx;
	int errcode;

	/* Keep track of time as we skip packets. */
	time = decoder->time;
	tcal = decoder->tcal;

	/* Keep track of a potential recovery point at MODE.TSX. */
	memset(&mode_tsx, 0, sizeof(mode_tsx));

	for (;;) {
		struct pt_packet packet;
		uint64_t offset;

		errcode = pt_pkt_get_offset(pkt, &offset);
		if (errcode < 0)
			return errcode;

		errcode = pt_pkt_next(pkt, &packet, sizeof(packet));
		if (errcode < 0) {
			/* Let's assume the trace is correct if we run out
			 * of packets.
			 */
			if (errcode == -pte_eos)
				errcode = 0;

			return errcode;
		}

		switch (packet.type) {
		case ppt_tip_pge:
			/* Everything is fine.  There is nothing to do. */
			return 0;

		case ppt_tip_pgd:
			/* This is a clear indication that the erratum
			 * applies.
			 *
			 * We synchronize after the disable.
			 */
			return skd010_recover_disabled(decoder, &tcal, &time,
						       offset + packet.size);

		case ppt_tnt_8:
		case ppt_tnt_64:
			/* This is a clear indication that the erratum
			 * apllies.
			 *
			 * Yet, we can't recover from it as we wouldn't know how
			 * many TNT bits will have been used when we eventually
			 * find an IP packet at which to resume tracing.
			 */
			return 0;

		case ppt_pip:
		case ppt_vmcs:
			/* We could track those changes and synthesize extra
			 * events after the overflow event when recovering from
			 * the erratum.  This requires infrastructure that we
			 * don't currently have, though, so we're not going to
			 * do it.
			 *
			 * Instead, we ignore those changes.  We already don't
			 * know how many other changes were lost in the
			 * overflow.
			 */
			break;

		case ppt_mode:
			switch (packet.payload.mode.leaf) {
			case pt_mol_exec:
				/* A MODE.EXEC packet binds to TIP, i.e.
				 *
				 *   TIP.PGE:  everything is fine
				 *   TIP:      the erratum applies
				 *
				 * In the TIP.PGE case, we may just follow the
				 * normal code flow.
				 *
				 * In the TIP case, we'd be able to re-sync at
				 * the TIP IP but have to skip packets up to and
				 * including the TIP.
				 *
				 * We'd need to synthesize the MODE.EXEC event
				 * after the overflow event when recovering at
				 * the TIP.  We lack the infrastructure for this
				 * - it's getting too complicated.
				 *
				 * Instead, we ignore the execution mode change;
				 * we already don't know how many more such
				 * changes were lost in the overflow.
				 */
				break;

			case pt_mol_tsx:
				/* A MODE.TSX packet may be standalone or bind
				 * to FUP.
				 *
				 * If this is the second MODE.TSX, we're sure
				 * that tracing is disabled and everything is
				 * fine.
				 */
				if (mode_tsx.offset)
					return 0;

				/* If we find the FUP this packet binds to, we
				 * may recover at the FUP IP and restart
				 * processing packets from here.  Remember the
				 * current state.
				 */
				mode_tsx.offset = offset;
				mode_tsx.time = time;
				mode_tsx.tcal = tcal;

				break;
			}

			break;

		case ppt_fup:
			/* This is a pretty good indication that tracing
			 * is indeed enabled and the erratum applies.
			 */

			/* If we got a MODE.TSX packet before, we synchronize at
			 * the FUP IP but continue decoding packets starting
			 * from the MODE.TSX.
			 */
			if (mode_tsx.offset)
				return skd010_recover(decoder,
						      &packet.payload.ip,
						      &mode_tsx.tcal,
						      &mode_tsx.time,
						      mode_tsx.offset);

			/* Without a preceding MODE.TSX, this FUP is the start
			 * of an async branch or disable.  We synchronize at the
			 * FUP IP and continue decoding packets from here.
			 */
			return skd010_recover(decoder, &packet.payload.ip,
					      &tcal, &time, offset);

		case ppt_tip:
			/* We syhchronize at the TIP IP and continue decoding
			 * packets after the TIP packet.
			 */
			return skd010_recover(decoder, &packet.payload.ip,
					      &tcal, &time,
					      offset + packet.size);

		case ppt_psb:
			/* We reached a synchronization point.  Tracing is
			 * enabled if and only if the PSB+ contains a FUP.
			 */
			errcode = pt_qry_find_header_fup(&packet, pkt);
			if (errcode < 0) {
				/* If we ran out of packets, we can't tell.
				 * Let's assume the trace is correct.
				 */
				if (errcode == -pte_eos)
					errcode = 0;

				return errcode;
			}

			/* If there is no FUP, tracing is disabled and
			 * everything is fine.
			 */
			if (!errcode)
				return 0;

			/* We should have a FUP. */
			if (packet.type != ppt_fup)
				return -pte_internal;

			/* Otherwise, we may synchronize at the FUP IP and
			 * continue decoding packets at the PSB.
			 */
			return skd010_recover(decoder, &packet.payload.ip,
					      &tcal, &time, offset);

		case ppt_psbend:
			/* We shouldn't see this. */
			return -pte_bad_context;

		case ppt_ovf:
		case ppt_stop:
			/* It doesn't matter if it had been enabled or disabled
			 * before.  We may resume normally.
			 */
			return 0;

		case ppt_unknown:
		case ppt_invalid:
			/* We can't skip this packet. */
			return 0;

		case ppt_pad:
		case ppt_mnt:
		case ppt_pwre:
		case ppt_pwrx:
			/* Ignore this packet. */
			break;

		case ppt_exstop:
			/* We may skip a stand-alone EXSTOP. */
			if (!packet.payload.exstop.ip)
				break;

			/* Fall through. */
		case ppt_mwait:
			/* To skip this packet, we'd need to take care of the
			 * FUP it binds to.  This is getting complicated.
			 */
			return 0;

		case ppt_ptw:
			/* We may skip a stand-alone PTW. */
			if (!packet.payload.ptw.ip)
				break;

			/* To skip this packet, we'd need to take care of the
			 * FUP it binds to.  This is getting complicated.
			 */
			return 0;

		case ppt_tsc:
			/* Keep track of time. */
			errcode = pt_qry_apply_tsc(&time, &tcal,
						   &packet.payload.tsc,
						   &decoder->config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cbr:
			/* Keep track of time. */
			errcode = pt_qry_apply_cbr(&time, &tcal,
						   &packet.payload.cbr,
						   &decoder->config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_tma:
			/* Keep track of time. */
			errcode = pt_qry_apply_tma(&time, &tcal,
						   &packet.payload.tma,
						   &decoder->config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_mtc:
			/* Keep track of time. */
			errcode = pt_qry_apply_mtc(&time, &tcal,
						   &packet.payload.mtc,
						   &decoder->config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cyc:
			/* Keep track of time. */
			errcode = pt_qry_apply_cyc(&time, &tcal,
						   &packet.payload.cyc,
						   &decoder->config);
			if (errcode < 0)
				return errcode;

			break;
		}
	}
}

static int pt_qry_handle_skd010(struct pt_query_decoder *decoder)
{
	struct pt_packet_decoder pkt;
	uint64_t offset;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_qry_get_offset(decoder, &offset);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_decoder_init(&pkt, &decoder->config);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_set(&pkt, offset);
	if (errcode >= 0)
		errcode = skd010_scan_for_ovf_resume(&pkt, decoder);

	pt_pkt_decoder_fini(&pkt);
	return errcode;
}

static int pt_pkt_find_ovf_fup(struct pt_packet_decoder *decoder)
{
	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (errcode < 0)
			return errcode;

		switch (packet.type) {
		case ppt_fup:
			return 1;

		case ppt_invalid:
			return -pte_bad_opc;

		case ppt_unknown:
		case ppt_pad:
		case ppt_mnt:
		case ppt_cbr:
		case ppt_tsc:
		case ppt_tma:
		case ppt_mtc:
		case ppt_cyc:
			continue;

		case ppt_psb:
		case ppt_tip_pge:
		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_stop:
		case ppt_ovf:
		case ppt_exstop:
		case ppt_mwait:
		case ppt_pwre:
		case ppt_pwrx:
		case ppt_ptw:
			return 0;

		case ppt_psbend:
		case ppt_tip:
		case ppt_tip_pgd:
		case ppt_tnt_8:
		case ppt_tnt_64:
			return -pte_bad_context;
		}
	}
}

/* Find a FUP to which the current OVF may bind.
 *
 * Scans the trace for a FUP or for a packet that indicates that tracing is
 * disabled.
 *
 * Return a positive integer if a FUP is found.
 * Returns zero if no FUP is found and tracing is assumed to be disabled.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_qry_find_ovf_fup(const struct pt_query_decoder *decoder)
{
	struct pt_packet_decoder pkt;
	uint64_t offset;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_qry_get_offset(decoder, &offset);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_decoder_init(&pkt, &decoder->config);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_set(&pkt, offset);
	if (errcode >= 0)
		errcode = pt_pkt_find_ovf_fup(&pkt);

	pt_pkt_decoder_fini(&pkt);
	return errcode;
}

int pt_qry_decode_ovf(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	struct pt_time time;
	int status, errcode;

	status = pt_qry_process_pending_psb_events(decoder);
	if (status < 0)
		return status;

	/* If we have any pending psbend events, we're done for now. */
	if (status)
		return 0;

	/* Reset the decoder state but preserve timing. */
	time = decoder->time;
	pt_qry_reset(decoder);
	decoder->time = time;

	/* We must consume the OVF before we search for the binding packet. */
	decoder->pos += ptps_ovf;

	/* Overflow binds to either FUP or TIP.PGE.
	 *
	 * If the overflow can be resolved while PacketEn=1 it binds to FUP.  We
	 * can see timing packets between OVF anf FUP but that's it.
	 *
	 * Otherwise, PacketEn will be zero when the overflow resolves and OVF
	 * binds to TIP.PGE.  There can be packets between OVF and TIP.PGE that
	 * do not depend on PacketEn.
	 *
	 * We don't need to decode everything until TIP.PGE, however.  As soon
	 * as we see a non-timing non-FUP packet, we know that tracing has been
	 * disabled before the overflow resolves.
	 */
	status = pt_qry_find_ovf_fup(decoder);
	if (status <= 0) {
		/* Check for erratum SKD010.
		 *
		 * The FUP may have been dropped.  If we can figure out that
		 * tracing is enabled and hence the FUP is missing, we resume
		 * at a later packet and a different IP.
		 */
		if (decoder->config.errata.skd010) {
			errcode = pt_qry_handle_skd010(decoder);
			if (errcode < 0)
				return errcode;

			if (errcode)
				return 0;
		}

		/* Report the original error from searching for the FUP packet
		 * if we were not able to fix the trace.
		 *
		 * We treat an overflow at the end of the trace as standalone.
		 */
		if (status < 0 && status != -pte_eos)
			return status;

		ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;

		ev->type = ptev_overflow;

		/* We suppress the IP to indicate that tracing has been
		 * disabled before the overflow resolved.  There can be
		 * several events before tracing is enabled again.
		 */
		ev->ip_suppressed = 1;

		/* Publish the event. */
		decoder->event = ev;
	} else {
		ev = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!ev)
			return -pte_internal;

		ev->type = ptev_overflow;

		/* We set tracing to disabled in pt_qry_reset(); fix it. */
		decoder->enabled = 1;
	}

	pt_qry_add_event_time(ev, decoder);

	return 0;
}

static int pt_qry_decode_mode_exec(struct pt_query_decoder *decoder,
				   const struct pt_packet_mode_exec *packet)
{
	struct pt_event *event;

	/* MODE.EXEC binds to TIP. */
	event = pt_evq_enqueue(&decoder->evq, evb_tip);
	if (!event)
		return -pte_nomem;

	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = pt_get_exec_mode(packet);

	pt_qry_add_event_time(event, decoder);

	return 0;
}

static int pt_qry_decode_mode_tsx(struct pt_query_decoder *decoder,
				  const struct pt_packet_mode_tsx *packet)
{
	struct pt_event *event;

	/* MODE.TSX is standalone if tracing is disabled. */
	if (!decoder->enabled) {
		event = pt_evq_standalone(&decoder->evq);
		if (!event)
			return -pte_internal;

		/* We don't have an IP in this case. */
		event->variant.tsx.ip = 0;
		event->ip_suppressed = 1;

		/* Publish the event. */
		decoder->event = event;
	} else {
		/* MODE.TSX binds to FUP. */
		event = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!event)
			return -pte_nomem;
	}

	event->type = ptev_tsx;
	event->variant.tsx.speculative = packet->intx;
	event->variant.tsx.aborted = packet->abrt;

	pt_qry_add_event_time(event, decoder);

	return 0;
}

int pt_qry_decode_mode(struct pt_query_decoder *decoder)
{
	struct pt_packet_mode packet;
	int size, errcode;

	size = pt_pkt_read_mode(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = 0;
	switch (packet.leaf) {
	case pt_mol_exec:
		errcode = pt_qry_decode_mode_exec(decoder, &packet.bits.exec);
		break;

	case pt_mol_tsx:
		errcode = pt_qry_decode_mode_tsx(decoder, &packet.bits.tsx);
		break;
	}

	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_header_mode(struct pt_query_decoder *decoder)
{
	struct pt_packet_mode packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_mode(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* Inside the header, events are reported at the end. */
	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!event)
		return -pte_nomem;

	switch (packet.leaf) {
	case pt_mol_exec:
		event->type = ptev_exec_mode;
		event->variant.exec_mode.mode =
			pt_get_exec_mode(&packet.bits.exec);
		break;

	case pt_mol_tsx:
		event->type = ptev_tsx;
		event->variant.tsx.speculative = packet.bits.tsx.intx;
		event->variant.tsx.aborted = packet.bits.tsx.abrt;
		break;
	}

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_psbend(struct pt_query_decoder *decoder)
{
	int status;

	status = pt_qry_process_pending_psb_events(decoder);
	if (status < 0)
		return status;

	/* If we had any psb events, we're done for now. */
	if (status)
		return 0;

	/* Skip the psbend extended opcode that we fetched before if no more
	 * psbend events are pending.
	 */
	decoder->pos += ptps_psbend;
	return 0;
}

int pt_qry_decode_tsc(struct pt_query_decoder *decoder)
{
	struct pt_packet_tsc packet;
	int size, errcode;

	size = pt_pkt_read_tsc(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_tsc(&decoder->time, &decoder->tcal,
				   &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_header_tsc(struct pt_query_decoder *decoder)
{
	struct pt_packet_tsc packet;
	int size, errcode;

	size = pt_pkt_read_tsc(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_header_tsc(&decoder->time, &decoder->tcal,
					  &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_cbr(struct pt_query_decoder *decoder)
{
	struct pt_packet_cbr packet;
	struct pt_event *event;
	int size, errcode;

	size = pt_pkt_read_cbr(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_cbr(&decoder->time, &decoder->tcal,
				   &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_cbr;
	event->variant.cbr.ratio = packet.ratio;

	pt_qry_add_event_time(event, decoder);

	decoder->event = event;
	decoder->pos += size;
	return 0;
}

int pt_qry_header_cbr(struct pt_query_decoder *decoder)
{
	struct pt_packet_cbr packet;
	struct pt_event *event;
	int size, errcode;

	size = pt_pkt_read_cbr(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_header_cbr(&decoder->time, &decoder->tcal,
					  &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!event)
		return -pte_nomem;

	event->type = ptev_cbr;
	event->variant.cbr.ratio = packet.ratio;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tma(struct pt_query_decoder *decoder)
{
	struct pt_packet_tma packet;
	int size, errcode;

	size = pt_pkt_read_tma(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_tma(&decoder->time, &decoder->tcal,
				   &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_mtc(struct pt_query_decoder *decoder)
{
	struct pt_packet_mtc packet;
	int size, errcode;

	size = pt_pkt_read_mtc(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_qry_apply_mtc(&decoder->time, &decoder->tcal,
				   &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

static int check_erratum_skd007(struct pt_query_decoder *decoder,
				const struct pt_packet_cyc *packet, int size)
{
	const uint8_t *pos;
	uint16_t payload;

	if (!decoder || !packet || size < 0)
		return -pte_internal;

	/* It must be a 2-byte CYC. */
	if (size != 2)
		return 0;

	payload = (uint16_t) packet->value;

	/* The 2nd byte of the CYC payload must look like an ext opcode. */
	if ((payload & ~0x1f) != 0x20)
		return 0;

	/* Skip this CYC packet. */
	pos = decoder->pos + size;
	if (decoder->config.end <= pos)
		return 0;

	/* See if we got a second CYC that looks like an OVF ext opcode. */
	if (*pos != pt_ext_ovf)
		return 0;

	/* We shouldn't get back-to-back CYCs unless they are sent when the
	 * counter wraps around.  In this case, we'd expect a full payload.
	 *
	 * Since we got two non-full CYC packets, we assume the erratum hit.
	 */

	return 1;
}

int pt_qry_decode_cyc(struct pt_query_decoder *decoder)
{
	struct pt_packet_cyc packet;
	struct pt_config *config;
	int size, errcode;

	config = &decoder->config;

	size = pt_pkt_read_cyc(&packet, decoder->pos, config);
	if (size < 0)
		return size;

	if (config->errata.skd007) {
		errcode = check_erratum_skd007(decoder, &packet, size);
		if (errcode < 0)
			return errcode;

		/* If the erratum hits, we ignore the partial CYC and instead
		 * process the OVF following/overlapping it.
		 */
		if (errcode) {
			/* We skip the first byte of the CYC, which brings us
			 * to the beginning of the OVF packet.
			 */
			decoder->pos += 1;
			return 0;
		}
	}

	errcode = pt_qry_apply_cyc(&decoder->time, &decoder->tcal,
				   &packet, config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_stop(struct pt_query_decoder *decoder)
{
	struct pt_event *event;

	/* Stop events are reported immediately. */
	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_stop;

	pt_qry_add_event_time(event, decoder);

	decoder->event = event;
	decoder->pos += ptps_stop;
	return 0;
}

int pt_qry_header_vmcs(struct pt_query_decoder *decoder)
{
	struct pt_packet_vmcs packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_vmcs(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!event)
		return -pte_nomem;

	event->type = ptev_async_vmcs;
	event->variant.async_vmcs.base = packet.base;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_vmcs(struct pt_query_decoder *decoder)
{
	struct pt_packet_vmcs packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_vmcs(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* VMCS events bind to the same IP as an in-flight async paging event.
	 *
	 * In that case, the VMCS event should be applied first.  We reorder
	 * events here to simplify the life of higher layers.
	 */
	event = pt_evq_find(&decoder->evq, evb_tip, ptev_async_paging);
	if (event) {
		struct pt_event *paging;

		paging = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!paging)
			return -pte_nomem;

		*paging = *event;

		event->type = ptev_async_vmcs;
		event->variant.async_vmcs.base = packet.base;

		decoder->pos += size;
		return 0;
	}

	/* VMCS events bind to the same TIP packet as an in-flight async
	 * branch event.
	 */
	event = pt_evq_find(&decoder->evq, evb_tip, ptev_async_branch);
	if (event) {
		event = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!event)
			return -pte_nomem;

		event->type = ptev_async_vmcs;
		event->variant.async_vmcs.base = packet.base;

		decoder->pos += size;
		return 0;
	}

	/* VMCS events that do not bind to an in-flight async event are
	 * stand-alone.
	 */
	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_vmcs;
	event->variant.vmcs.base = packet.base;

	pt_qry_add_event_time(event, decoder);

	decoder->event = event;
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_mnt(struct pt_query_decoder *decoder)
{
	struct pt_packet_mnt packet;
	struct pt_event *event;
	int size;

	if (!decoder)
		return -pte_internal;

	size = pt_pkt_read_mnt(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_mnt;
	event->variant.mnt.payload = packet.payload;

	pt_qry_add_event_time(event, decoder);

	decoder->event = event;
	decoder->pos += size;

	return 0;
}

int pt_qry_header_mnt(struct pt_query_decoder *decoder)
{
	struct pt_packet_mnt packet;
	struct pt_event *event;
	int size;

	if (!decoder)
		return -pte_internal;

	size = pt_pkt_read_mnt(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!event)
		return -pte_nomem;

	event->type = ptev_mnt;
	event->variant.mnt.payload = packet.payload;

	decoder->pos += size;

	return 0;
}

int pt_qry_decode_exstop(struct pt_query_decoder *decoder)
{
	struct pt_packet_exstop packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_exstop(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	if (packet.ip) {
		event = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!event)
			return -pte_internal;

		event->type = ptev_exstop;
	} else {
		event = pt_evq_standalone(&decoder->evq);
		if (!event)
			return -pte_internal;

		event->type = ptev_exstop;

		event->ip_suppressed = 1;
		event->variant.exstop.ip = 0ull;

		decoder->event = event;
	}

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_mwait(struct pt_query_decoder *decoder)
{
	struct pt_packet_mwait packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_mwait(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_enqueue(&decoder->evq, evb_fup);
	if (!event)
		return -pte_internal;

	event->type = ptev_mwait;
	event->variant.mwait.hints = packet.hints;
	event->variant.mwait.ext = packet.ext;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_pwre(struct pt_query_decoder *decoder)
{
	struct pt_packet_pwre packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_pwre(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_pwre;
	event->variant.pwre.state = packet.state;
	event->variant.pwre.sub_state = packet.sub_state;

	if (packet.hw)
		event->variant.pwre.hw = 1;

	decoder->event = event;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_pwrx(struct pt_query_decoder *decoder)
{
	struct pt_packet_pwrx packet;
	struct pt_event *event;
	int size;

	size = pt_pkt_read_pwrx(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	event = pt_evq_standalone(&decoder->evq);
	if (!event)
		return -pte_internal;

	event->type = ptev_pwrx;
	event->variant.pwrx.last = packet.last;
	event->variant.pwrx.deepest = packet.deepest;

	if (packet.interrupt)
		event->variant.pwrx.interrupt = 1;
	if (packet.store)
		event->variant.pwrx.store = 1;
	if (packet.autonomous)
		event->variant.pwrx.autonomous = 1;

	decoder->event = event;

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_ptw(struct pt_query_decoder *decoder)
{
	struct pt_packet_ptw packet;
	struct pt_event *event;
	int size, pls;

	size = pt_pkt_read_ptw(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	pls = pt_ptw_size(packet.plc);
	if (pls < 0)
		return pls;

	if (packet.ip) {
		event = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!event)
			return -pte_internal;
	} else {
		event = pt_evq_standalone(&decoder->evq);
		if (!event)
			return -pte_internal;

		event->ip_suppressed = 1;

		decoder->event = event;
	}

	event->type = ptev_ptwrite;
	event->variant.ptwrite.size = (uint8_t) pls;
	event->variant.ptwrite.payload = packet.payload;

	decoder->pos += size;
	return 0;
}
