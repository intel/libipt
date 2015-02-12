/*
 * Copyright (c) 2014-2015, Intel Corporation
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

#include "intel-pt.h"

#include <string.h>
#include <stddef.h>


int pt_qry_decoder_init(struct pt_query_decoder *decoder,
			const struct pt_config *config)
{
	if (!decoder || !config)
		return -pte_invalid;

	if (config->size != sizeof(*config))
		return -pte_bad_config;

	if (!config->begin || !config->end)
		return -pte_bad_config;

	if (config->end < config->begin)
		return -pte_bad_config;

	memset(decoder, 0, sizeof(*decoder));

	decoder->config = *config;

	pt_last_ip_init(&decoder->ip);
	pt_tnt_cache_init(&decoder->tnt);
	pt_time_init(&decoder->time);
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
	if (pt_tnt_cache_is_empty(&decoder->tnt) && pt_qry_will_event(decoder))
		flags |= pts_event_pending;

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

	/* Read ahead until the first query-relevant packet.
	 * We ignore errors; they will be diagnosed in the first query.
	 */
	(void) pt_qry_read_ahead(decoder);

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
	const uint8_t *pos, *sync;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	pos = decoder->sync;
	if (!pos)
		pos = decoder->config.end;

	errcode = pt_sync_backward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	return pt_qry_start(decoder, sync, ip);
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

int pt_qry_get_offset(struct pt_query_decoder *decoder, uint64_t *offset)
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

int pt_qry_get_sync_offset(struct pt_query_decoder *decoder, uint64_t *offset)
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

static int pt_qry_cache_tnt(struct pt_query_decoder *decoder)
{
	for (;;) {
		const struct pt_decoder_function *dfun;
		int errcode;

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
			return -pte_nosync;

		/* We're done when we decoded a TNT packet. */
		if (dfun->flags & pdff_tnt)
			break;

		/* Read ahead until the next query-relevant packet. */
		errcode = pt_qry_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Read ahead until the next query-relevant packet. */
	(void) pt_qry_read_ahead(decoder);

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
		errcode = pt_qry_read_ahead(decoder);
		if (errcode)
			return errcode;
	}

	/* Read ahead until the next query-relevant packet. */
	(void) pt_qry_read_ahead(decoder);

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

	/* Read ahead until the next query-relevant packet. */
	(void) pt_qry_read_ahead(decoder);

	flags |= pt_qry_status_flags(decoder);

	return flags;
}

int pt_qry_time(struct pt_query_decoder *decoder, uint64_t *time)
{
	if (!decoder || !time)
		return -pte_invalid;

	return pt_time_query_tsc(time, &decoder->time);
}

int pt_qry_core_bus_ratio(struct pt_query_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	return pt_time_query_cbr(cbr, &decoder->time);
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
	int size, errcode;

	size = pt_pkt_read_psb(decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	decoder->pos += size;

	errcode = pt_qry_read_psb_header(decoder);
	if (errcode < 0)
		return errcode;

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

			case ptev_overflow: {
				uint64_t ip;
				int errcode;

				/* We can't afford a suppressed IP, here. */
				errcode = pt_last_ip_query(&ip, &decoder->ip);
				if (errcode < 0)
					return -pte_bad_packet;

				ev->variant.overflow.ip = ip;
			}
				break;

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

		errcode = pt_pkt_next(decoder, &packet);
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

		decoder->event = event;
	} else {
		event = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!event)
			return -pte_nomem;

		event->type = ptev_async_paging;
		event->variant.async_paging.cr3 = packet.cr3;
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

	event->type = ptev_paging;
	event->variant.paging.cr3 = packet.cr3;

	decoder->pos += size;
	return 0;
}

static int pt_qry_prepare_psb_event(struct pt_event *ev)
{
	if (!ev)
		return -pte_internal;

	/* Turn paging events into async paging events since the IP is not
	 * obvious from the code.
	 */
	if (ev->type == ptev_paging) {
		uint64_t cr3;

		cr3 = ev->variant.paging.cr3;

		ev->type = ptev_async_paging;
		ev->variant.async_paging.cr3 = cr3;
	}

	/* Mark the event as status update. */
	ev->status_update = 1;

	return 0;
}

static int pt_qry_process_pending_psb_events(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	ev = pt_evq_dequeue(&decoder->evq, evb_psbend);
	if (!ev)
		return 0;

	errcode = pt_qry_prepare_psb_event(ev);
	if (errcode < 0)
		return errcode;

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
	}

	/* Publish the event. */
	decoder->event = ev;

	/* Signal a pending event. */
	return 1;
}

int pt_qry_decode_ovf(struct pt_query_decoder *decoder)
{
	struct pt_event *ev;
	int status, enabled;
	enum pt_event_binding evb;

	status = pt_qry_process_pending_psb_events(decoder);
	if (status < 0)
		return status;

	/* If we have any pending psbend events, we're done for now. */
	if (status)
		return 0;

	/* Reset the decoder state - but preserve trace enabling.
	 *
	 * We don't know how many packets we lost so any queued events or unused
	 * TNT bits will likely be wrong.
	 */
	enabled = decoder->enabled;

	pt_qry_reset(decoder);

	if (enabled)
		decoder->enabled = 1;

	/* OVF binds to FUP as long as tracing is enabled.
	 * It binds to TIP.PGE when tracing is disabled.
	 */
	evb = enabled ? evb_fup : evb_tip;

	/* Queue the overflow event.
	 *
	 * We must be able to enqueue the overflow event since we just reset
	 * the decoder state.
	 */
	ev = pt_evq_enqueue(&decoder->evq, evb);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;

	decoder->pos += ptps_ovf;
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
	int size;

	size = pt_pkt_read_tsc(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* Ignore time update errors.  Timing will be off but we should still
	 * be able to decode the instruction trace.
	 */
	(void) pt_time_update_tsc(&decoder->time, &packet, &decoder->config);

	decoder->pos += size;
	return 0;
}

int pt_qry_decode_cbr(struct pt_query_decoder *decoder)
{
	struct pt_packet_cbr packet;
	int size;

	size = pt_pkt_read_cbr(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	/* Ignore time update errors.  Timing will be off but we should still
	 * be able to decode the instruction trace.
	 */
	(void) pt_time_update_cbr(&decoder->time, &packet, &decoder->config);

	decoder->pos += size;
	return 0;
}
