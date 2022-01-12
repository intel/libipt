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

#include "pt_query_decoder.h"
#include "pt_config.h"
#include "pt_opcodes.h"
#include "pt_compiler.h"

#include "intel-pt.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>


/* Initialize the event decoder flags based on our flags. */

static int pt_qry_init_evt_flags(struct pt_conf_flags *eflags,
				 const struct pt_conf_flags *flags)
{
	if (!eflags || !flags)
		return -pte_internal;

	memset(eflags, 0, sizeof(*eflags));
	eflags->variant.event.keep_tcal_on_ovf =
		flags->variant.query.keep_tcal_on_ovf;

	return 0;
}

static int pt_qry_reset(struct pt_query_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->status = -pte_nosync;

	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->last_time);

	return 0;
}

int pt_qry_decoder_init(struct pt_query_decoder *decoder,
			const struct pt_config *uconfig)
{
	struct pt_config config;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_config_from_user(&config, uconfig);
	if (errcode < 0)
		return errcode;

	/* The user supplied decoder flags. */
	decoder->flags = config.flags;

	/* Set the flags we need for the event decoder we use. */
	errcode = pt_qry_init_evt_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_decoder_init(&decoder->evdec, &config);
	if (errcode < 0)
		return errcode;

	return pt_qry_reset(decoder);
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
	if (!decoder)
		return;

	pt_evt_decoder_fini(&decoder->evdec);
}

void pt_qry_free_decoder(struct pt_query_decoder *decoder)
{
	pt_qry_decoder_fini(decoder);
	free(decoder);
}

static int pt_qry_event_pending(const struct pt_event *ev)
{
	if (!ev)
		return -pte_internal;

	switch (ev->type) {
	case ptev_tnt:
	case ptev_tip:
		return 0;

	default:
		return 1;
	}
}

static int pt_qry_status_flags(const struct pt_query_decoder *decoder)
{
	int errcode, flags;

	if (!decoder)
		return -pte_internal;

	flags = 0;

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
		if (decoder->status < 0) {
			if (decoder->status == -pte_eos)
				flags |= pts_eos;
		} else {
			errcode = pt_qry_event_pending(&decoder->event);
			if (errcode != 0) {
				if (errcode < 0)
					return errcode;

				flags |= pts_event_pending;
			}
		}

	}

	return flags;
}

static int pt_qry_fetch_event(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	errcode = pt_evt_next(&decoder->evdec, ev, sizeof(*ev));
	if (errcode < 0) {
		decoder->status = errcode;
		memset(ev, 0xff, sizeof(*ev));
	}

	return 0;
}

static int pt_qry_start(struct pt_query_decoder *decoder, uint64_t *ip)
{
	struct pt_event_decoder evdec;
	struct pt_event ev;
	int errcode, flags, status;

	if (!decoder)
		return -pte_invalid;

	/* We need to process satus update events from PSB+ in order to
	 * provide the start IP.
	 *
	 * On the other hand, we need to provide those same status events to
	 * our user.  We do that by using a local copy of our event decoder, so
	 * when we're done, we rewind back to where we started.
	 */
	evdec = decoder->evdec;

	status = pts_ip_suppressed;

	/* Process status update events from PSB+ to initialize our state. */
	for (;;) {
		/* Check that we're still processing the initial events.
		 *
		 * When the event decoder moves ahead, we're done with the
		 * initial PSB+.  We may get additional events from an adjacent
		 * PSB+, but we don't want to process them here.
		 */
		if (pt_evt_pos(&evdec) != pt_qry_pos(decoder))
			break;

		errcode = pt_evt_next(&evdec, &ev, sizeof(ev));
		if (errcode < 0) {
			if (errcode != -pte_eos)
				return errcode;

			break;
		}

		if (!ev.status_update)
			break;

		switch (ev.type) {
		case ptev_enabled:
			status &= ~pts_ip_suppressed;
			if (ip)
				*ip = ev.variant.enabled.ip;

			break;

		default:
			continue;
		}

		break;
	}

	decoder->status = 0;

	errcode = pt_qry_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	flags = pt_qry_status_flags(decoder);
	if (flags < 0)
		return flags;

	status |= flags;

	return status;
}

int pt_qry_sync_forward(struct pt_query_decoder *decoder, uint64_t *ip)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_qry_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_sync_forward(&decoder->evdec);
	if (errcode < 0)
		return errcode;

	return pt_qry_start(decoder, ip);
}

int pt_qry_sync_backward(struct pt_query_decoder *decoder, uint64_t *ip)
{
	const uint8_t *start, *sync, *pos;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	start = pt_qry_pos(decoder);
	if (!start) {
		const struct pt_config *config;

		config = pt_qry_config(decoder);
		if (!config)
			return -pte_internal;

		start = config->end;
		if (!start)
			return -pte_bad_config;
	}

	sync = start;
	for (;;) {
		errcode = pt_qry_reset(decoder);
		if (errcode < 0)
			return errcode;

		do {
			errcode = pt_evt_sync_backward(&decoder->evdec);
			if (errcode < 0)
				return errcode;

			pos = pt_qry_pos(decoder);
		} while (sync <= pos);

		sync = pos;

		errcode = pt_qry_start(decoder, ip);
		if (errcode < 0) {
			/* Ignore incomplete trace segments at the end.  We
			 * need a full PSB+ to start decoding.
			 */
			if (errcode != -pte_eos)
				return errcode;

			continue;
		}

		/* When starting inside or right after PSB+, we may end up at
		 * the same PSB again.  Skip it.
		 */
		pos = pt_qry_pos(decoder);
		if (pos < start)
			break;
	}

	return 0;
}

int pt_qry_sync_set(struct pt_query_decoder *decoder, uint64_t *ip,
		    uint64_t offset)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_qry_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_sync_set(&decoder->evdec, offset);
	if (errcode < 0)
		return errcode;

	return pt_qry_start(decoder, ip);
}

int pt_qry_get_offset(const struct pt_query_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_evt_get_offset(&decoder->evdec, offset);
}

int pt_qry_get_sync_offset(const struct pt_query_decoder *decoder,
			   uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_evt_get_sync_offset(&decoder->evdec, offset);
}

const struct pt_config *
pt_qry_get_config(const struct pt_query_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_evt_get_config(&decoder->evdec);
}

static int pt_qry_cache_tnt(struct pt_query_decoder *decoder)
{
	const struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	/* Check if the current event is valid. */
	errcode = decoder->status;
	if (errcode < 0)
		return errcode;

	/* If we don't have a TNT event, there's nothing to do. */
	ev = &decoder->event;
	if (ev->type != ptev_tnt)
		return 0;

	errcode = pt_tnt_cache_add(&decoder->tnt, ev->variant.tnt.bits,
				   ev->variant.tnt.size);
	if (errcode < 0)
		return errcode;

	return pt_qry_fetch_event(decoder);
}

int pt_qry_cond_branch(struct pt_query_decoder *decoder, int *taken)
{
	int query;

	if (!decoder || !taken)
		return -pte_invalid;

	query = pt_tnt_cache_query(&decoder->tnt);
	if (query < 0) {
		int errcode;

		if (query != -pte_bad_query)
			return query;

		/* If we ran out of TNT bits, check if the current event
		 * provides any.
		 *
		 * Preserve the time at the TNT event.
		 */
		decoder->last_time = decoder->evdec.time;

		errcode = pt_qry_cache_tnt(decoder);
		if (errcode < 0)
			return errcode;

		query = pt_tnt_cache_query(&decoder->tnt);
		if (query < 0) {
			if (query != -pte_bad_query)
				return query;

			/* Report any deferred event decode errors.
			 *
			 * We deferred them until we consumed the last TNT bit
			 * in our cache.
			 */
			errcode = decoder->status;
			if (errcode < 0)
				return errcode;

			return query;
		}
	}

	*taken = query;

	return pt_qry_status_flags(decoder);
}

int pt_qry_indirect_branch(struct pt_query_decoder *decoder, uint64_t *addr)
{
	const struct pt_event *ev;
	int errcode, status, flags;

	if (!decoder || !addr)
		return -pte_invalid;

	/* Report any deferred error. */
	errcode = decoder->status;
	if (errcode < 0)
		return errcode;

	ev = &decoder->event;
	if (ev->type != ptev_tip) {
		/* Fill our TNT cache if we have a TNT packet. */
		errcode = pt_qry_cache_tnt(decoder);
		if (errcode < 0)
			return errcode;

		/* Check again.  We may have fetched a new packet. */
		if (ev->type != ptev_tip) {
			errcode = decoder->status;
			if (errcode < 0)
				return errcode;

			return -pte_bad_query;
		}
	}

	status = 0;
	if (ev->ip_suppressed)
		status |= pts_ip_suppressed;
	else
		*addr = ev->variant.tip.ip;

	/* Preserve the time at the TIP event. */
	decoder->last_time = decoder->evdec.time;

	errcode = pt_qry_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	flags = pt_qry_status_flags(decoder);
	if (flags < 0)
		return flags;

	status |= flags;

	return status;
}

int pt_qry_event(struct pt_query_decoder *decoder, struct pt_event *uev,
		 size_t size)
{
	const struct pt_event *ev;
	int errcode, status;

	if (!decoder || !uev)
		return -pte_invalid;

	if (size < offsetof(struct pt_event, variant))
		return -pte_invalid;

	/* We do not allow querying for events while there are still TNT
	 * bits to consume.
	 */
	if (!pt_tnt_cache_is_empty(&decoder->tnt))
		return -pte_bad_query;

	/* Report any deferred error. */
	errcode = decoder->status;
	if (errcode < 0)
		return errcode;

	ev = &decoder->event;

	status = pt_qry_event_pending(ev);
	if (status <= 0) {
		if (status < 0)
			return status;

		return -pte_bad_query;
	}

	/* Copy the event to the user.  Make sure we're not writing beyond the
	 * memory provided by the user.
	 *
	 * We might truncate details of an event but only for those events the
	 * user can't know about, anyway.
	 */
	if (sizeof(*uev) < size)
		size = sizeof(*uev);

	memcpy(uev, ev, size);

	/* Preserve the time at the event. */
	decoder->last_time = decoder->evdec.time;

	errcode = pt_qry_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	return pt_qry_status_flags(decoder);
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
