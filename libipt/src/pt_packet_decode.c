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

#include "pt_packet_decode.h"
#include "pt_decoder_function.h"
#include "pt_decoder.h"
#include "pt_packet.h"

#include "intel-pt.h"


int pt_pkt_decode_unknown(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_unknown(packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	return size;
}

int pt_qry_decode_unknown(struct pt_decoder *decoder)
{
	struct pt_packet packet;
	int size;

	size = pt_pkt_read_unknown(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

int pt_pkt_decode_pad(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	packet->type = ppt_pad;
	packet->size = ptps_pad;

	return ptps_pad;
}

int pt_qry_decode_pad(struct pt_decoder *decoder)
{
	decoder->pos += ptps_pad;

	return 0;
}

int pt_pkt_decode_psb(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_psb(decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_psb;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_header_psb(struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_psb(decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

static int pt_qry_read_psb_header(struct pt_decoder *decoder)
{
	pt_last_ip_init(&decoder->ip);

	for (;;) {
		const struct pt_decoder_function *dfun;
		int errcode;

		errcode = pt_fetch_decoder(decoder);
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

int pt_qry_decode_psb(struct pt_decoder *decoder)
{
	int errcode;

	errcode = pt_qry_header_psb(decoder);
	if (errcode < 0)
		return errcode;

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
				const struct pt_decoder *decoder)
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
static int pt_qry_decode_ip(struct pt_decoder *decoder)
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

int pt_pkt_decode_tip(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_qry_consume_tip(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip(struct pt_decoder *decoder)
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

			/* The event will consume the packet. */
			decoder->flags |= pdf_consume_packet;

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
		if (!(decoder->flags & pdf_consume_packet))
			return 0;

		/* We're done with this packet. Clear the flag we set previously
		 * and consume it.
		 */
		decoder->flags &= ~pdf_consume_packet;
	}

	return pt_qry_consume_tip(decoder, size);
}

int pt_pkt_decode_tnt_8(struct pt_packet *packet,
			const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_tnt_8(&packet->payload.tnt, decoder->pos,
				 &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_8;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_decode_tnt_8(struct pt_decoder *decoder)
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

int pt_pkt_decode_tnt_64(struct pt_packet *packet,
			 const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_tnt_64(&packet->payload.tnt, decoder->pos,
				  &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_64;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_decode_tnt_64(struct pt_decoder *decoder)
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

int pt_pkt_decode_tip_pge(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pge;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_qry_consume_tip_pge(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip_pge(struct pt_decoder *decoder)
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
	if (!(decoder->flags & pdf_consume_packet)) {
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

		/* Tracing is no longer disabled. */
		decoder->flags &= ~pdf_pt_disabled;

		/* Process pending events next. */
		decoder->flags |= pdf_consume_packet;
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
	if (!(decoder->flags & pdf_consume_packet))
		return -pte_internal;

	decoder->flags &= ~pdf_consume_packet;

	return pt_qry_consume_tip_pge(decoder, size);
}

int pt_pkt_decode_tip_pgd(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pgd;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_qry_consume_tip_pgd(struct pt_decoder *decoder, int size)
{
	decoder->flags |= pdf_pt_disabled;
	decoder->pos += size;
	return 0;
}

int pt_qry_decode_tip_pgd(struct pt_decoder *decoder)
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

int pt_pkt_decode_fup(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_fup;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_qry_consume_fup(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

int pt_qry_header_fup(struct pt_decoder *decoder)
{
	struct pt_packet_ip packet;
	int errcode, size;

	size = pt_pkt_read_ip(&packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	errcode = pt_last_ip_update_ip(&decoder->ip, &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* Tracing is enabled if we have an IP in the header. */
	if (packet.ipc != pt_ipc_suppressed)
		decoder->flags &= ~pdf_pt_disabled;

	return pt_qry_consume_fup(decoder, size);
}

int pt_qry_decode_fup(struct pt_decoder *decoder)
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

			/* The event will consume the packet. */
			decoder->flags |= pdf_consume_packet;
		}
			break;

		case ptev_tsx:
			pt_qry_add_event_ip(ev, &ev->variant.tsx.ip, decoder);

			/* A non-abort event will consume the packet. */
			if (!(ev->variant.tsx.aborted))
				decoder->flags |= pdf_consume_packet;

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
		if (!(decoder->flags & pdf_consume_packet))
			return 0;

		/* We're done with this packet. Clear the flag we set previously
		 * and consume it.
		 */
		decoder->flags &= ~pdf_consume_packet;
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

int pt_pkt_decode_pip(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_pip(&packet->payload.pip, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_pip;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_decode_pip(struct pt_decoder *decoder)
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

int pt_qry_header_pip(struct pt_decoder *decoder)
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

int pt_pkt_decode_ovf(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	packet->type = ppt_ovf;
	packet->size = ptps_ovf;

	return ptps_ovf;
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

static int pt_qry_process_pending_psb_events(struct pt_decoder *decoder)
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

int pt_qry_decode_ovf(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	uint64_t flags;
	int status;
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
	flags = decoder->flags;

	pt_reset(decoder);

	if (!(flags & pdf_pt_disabled))
		decoder->flags &= ~pdf_pt_disabled;

	/* OVF binds to FUP as long as tracing is enabled.
	 * It binds to TIP.PGE when tracing is disabled.
	 */
	evb = (flags & pdf_pt_disabled) ? evb_tip : evb_fup;

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

int pt_pkt_decode_mode(struct pt_packet *packet,
		       const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_mode(&packet->payload.mode, decoder->pos,
				&decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_mode;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_qry_decode_mode_exec(struct pt_decoder *decoder,
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

static int pt_qry_decode_mode_tsx(struct pt_decoder *decoder,
				  const struct pt_packet_mode_tsx *packet)
{
	struct pt_event *event;

	/* MODE.TSX is standalone if tracing is disabled. */
	if (decoder->flags & pdf_pt_disabled) {
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

int pt_qry_decode_mode(struct pt_decoder *decoder)
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

int pt_qry_header_mode(struct pt_decoder *decoder)
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

int pt_pkt_decode_psbend(struct pt_packet *packet,
			 const struct pt_decoder *decoder)
{
	packet->type = ppt_psbend;
	packet->size = ptps_psbend;

	return ptps_psbend;
}

int pt_qry_decode_psbend(struct pt_decoder *decoder)
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

int pt_pkt_decode_tsc(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_tsc(&packet->payload.tsc, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tsc;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_decode_tsc(struct pt_decoder *decoder)
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

int pt_pkt_decode_cbr(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = pt_pkt_read_cbr(&packet->payload.cbr, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_cbr;
	packet->size = (uint8_t) size;

	return size;
}

int pt_qry_decode_cbr(struct pt_decoder *decoder)
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
