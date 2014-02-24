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
#include "pt_decoder.h"

#include "intel-pt.h"

#include <inttypes.h>
#include <limits.h>


static int extract_unknown(struct pt_packet *packet,
			   const struct pt_decoder *decoder)
{
	int (*decode)(struct pt_packet_unknown *, const struct pt_config *,
		      const uint8_t *, void *);
	int size, errcode;

	decode = decoder->config.decode.callback;
	if (!decode)
		return -pte_bad_opc;

	/* Fill in some default values. */
	packet->payload.unknown.packet = decoder->pos;
	packet->payload.unknown.priv = NULL;

	/* We accept a size of zero to allow the callback to modify the
	 * trace buffer and resume normal decoding.
	 */
	size = (*decode)(&packet->payload.unknown, &decoder->config,
			 decoder->pos, decoder->config.decode.context);
	if (size < 0)
		return size;

	if (size > UCHAR_MAX)
		return -pte_invalid;

	packet->type = ppt_unknown;
	packet->size = (uint8_t) size;

	errcode = pt_check_bounds(decoder, size);
	if (errcode < 0)
		return errcode;

	return size;
}

static int packet_unknown(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = extract_unknown(packet, decoder);
	if (size < 0)
		return size;

	return size;
}

static int decode_unknown(struct pt_decoder *decoder)
{
	struct pt_packet packet;
	int size;

	size = extract_unknown(&packet, decoder);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_unknown = {
	/* .packet = */ packet_unknown,
	/* .decode = */ decode_unknown,
	/* .header = */ decode_unknown,
	/* .flags = */ pdff_unknown
};

static int packet_pad(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	packet->type = ppt_pad;
	packet->size = ptps_pad;

	return ptps_pad;
}

static int decode_pad(struct pt_decoder *decoder)
{
	decoder->pos += ptps_pad;

	return 0;
}

const struct pt_decoder_function pt_decode_pad = {
	/* .packet = */ packet_pad,
	/* .decode = */ decode_pad,
	/* .header = */ decode_pad,
	/* .flags = */ 0
};

static int extract_psb(const struct pt_decoder *decoder)
{
	const uint8_t *pos;
	int errcode, count;

	errcode = pt_check_bounds(decoder, ptps_psb);
	if (errcode < 0)
		return errcode;

	pos = decoder->pos + pt_opcs_psb;

	for (count = 0; count < pt_psb_repeat_count; ++count) {
		if (*pos++ != pt_psb_hi)
			return -pte_bad_packet;
		if (*pos++ != pt_psb_lo)
			return -pte_bad_packet;
	}

	return ptps_psb;
}

static int packet_psb(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_psb(decoder);
	if (size < 0)
		return size;

	packet->type = ppt_psb;
	packet->size = (uint8_t) size;

	return size;
}

static int header_psb(struct pt_decoder *decoder)
{
	int size;

	size = extract_psb(decoder);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

static int read_psb_header(struct pt_decoder *decoder)
{
	decoder->flags &= ~pdf_status_have_ip;

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

static int decode_psb(struct pt_decoder *decoder)
{
	int errcode;

	errcode = header_psb(decoder);
	if (errcode < 0)
		return errcode;

	errcode = read_psb_header(decoder);
	if (errcode < 0)
		return errcode;

	/* The next packet following the PSB header will be of type PSBEND.
	 *
	 * Decoding this packet will publish the PSB events what have been
	 * accumulated while reading the PSB header.
	 */
	return 0;
}

const struct pt_decoder_function pt_decode_psb = {
	/* .packet = */ packet_psb,
	/* .decode = */ decode_psb,
	/* .header = */ header_psb,
	/* .flags = */ 0
};

static uint64_t pt_read_value(const uint8_t *pos, int size)
{
	uint64_t val;
	int idx;

	for (val = 0, idx = 0; idx < size; ++idx) {
		uint64_t byte = *pos++;

		byte <<= (idx * 8);
		val |= byte;
	}

	return val;
}

static void fill_in_event_ip(struct pt_event *event, uint64_t *ip,
			     const struct pt_decoder *decoder)
{
	int errcode;

	errcode = pt_last_ip_query(ip, &decoder->ip);
	if (errcode < 0)
		event->ip_suppressed = 1;
}

static int extract_ip(struct pt_packet_ip *packet,
		      const struct pt_decoder *decoder)
{
	const uint8_t *pos;
	uint64_t ip;
	uint8_t ipc;
	int size, ipsize, errcode;

	pos = decoder->pos;
	ipc = (*pos++ >> pt_opm_ipc_shr) & pt_opm_ipc_shr_mask;

	size = 1;
	ipsize = 0;
	switch (ipc) {
	case pt_ipc_suppressed:
		ipsize = 0;
		break;

	case pt_ipc_update_16:
		ipsize = 2;
		break;

	case pt_ipc_update_32:
		ipsize = 4;
		break;

	case pt_ipc_sext_48:
		ipsize = 6;
		break;
	}

	size += ipsize;
	errcode = pt_check_bounds(decoder, size);
	if (errcode < 0)
		return errcode;

	ip = 0;
	if (ipsize)
		ip = pt_read_value(pos, ipsize);

	packet->ipc = (enum pt_ip_compression) ipc;
	packet->ip = ip;

	return size;
}

/* Decode a generic IP packet.
 *
 * Returns the number of bytes read, on success.
 * Returns -pte_eos if the ip does not fit into the buffer.
 * Returns -pte_bad_packet if the ip compression is not known.
 */
static int decode_ip(struct pt_decoder *decoder)
{
	struct pt_packet_ip packet;
	int errcode, size;

	size = extract_ip(&packet, decoder);
	if (size < 0)
		return size;

	errcode = pt_last_ip_update_ip(&decoder->ip, &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	/* We do not update the decoder's position, yet. */

	return size;
}

static int packet_tip(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_ip(&packet->payload.ip, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tip;
	packet->size = (uint8_t) size;

	return size;
}

static int consume_tip(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

static int decode_tip(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to TIP. */
	ev = pt_dequeue_event(decoder, evb_tip);
	if (ev) {
		switch (ev->type) {
		default:
			return -pte_internal;

		case ptev_async_branch:
			fill_in_event_ip(ev, &ev->variant.async_branch.to,
					 decoder);

			/* The event will consume the packet. */
			decoder->flags |= pdf_consume_packet;

			break;

		case ptev_async_paging:
			fill_in_event_ip(ev, &ev->variant.async_paging.ip,
					 decoder);
			break;

		case ptev_exec_mode:
			fill_in_event_ip(ev, &ev->variant.exec_mode.ip,
					 decoder);
			break;
		}

		/* Publish the event. */
		decoder->event = ev;

		/* Process further pending events. */
		if (pt_event_pending(decoder, evb_tip))
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

	return consume_tip(decoder, size);
}

const struct pt_decoder_function pt_decode_tip = {
	/* .packet = */ packet_tip,
	/* .decode = */ decode_tip,
	/* .header = */ NULL,
	/* .flags = */ pdff_tip
};

static uint8_t get_tnt_bit_size(uint64_t payload)
{
	uint8_t size;

	/* The payload bit-size is the bit-index of the payload's stop-bit,
	 * which itself is not part of the payload proper.
	 */
	for (size = 0; ; size += 1) {
		payload >>= 1;
		if (!payload)
			break;
	}

	return size;
}

static int extract_tnt_8(struct pt_packet_tnt *packet,
			 const struct pt_decoder *decoder)
{
	uint64_t payload;
	uint8_t bit_size;

	/* TNT-8 does not have a separate payload.  Skip the bounds check. */
	payload = *decoder->pos >> pt_opm_tnt_8_shr;

	bit_size = get_tnt_bit_size(payload);
	if (!bit_size)
		return -pte_bad_packet;

	/* Remove the stop bit from the payload. */
	payload &= ~(1ull << bit_size);

	packet->payload = payload;
	packet->bit_size = bit_size;

	return ptps_tnt_8;
}

static int packet_tnt_8(struct pt_packet *packet,
			const struct pt_decoder *decoder)
{
	int size;

	size = extract_tnt_8(&packet->payload.tnt, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_8;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_tnt_8(struct pt_decoder *decoder)
{
	struct pt_packet_tnt packet;
	int size, errcode;

	size = extract_tnt_8(&packet, decoder);
	if (size < 0)
		return size;

	errcode = pt_tnt_cache_update_tnt(&decoder->tnt, &packet,
					  &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_tnt_8 = {
	/* .packet = */ packet_tnt_8,
	/* .decode = */ decode_tnt_8,
	/* .header = */ NULL,
	/* .flags = */ pdff_tnt
};

static int extract_tnt_64(struct pt_packet_tnt *packet,
			  const struct pt_decoder *decoder)
{
	uint64_t payload;
	uint8_t bit_size;
	int errcode;

	errcode = pt_check_bounds(decoder, ptps_tnt_64);
	if (errcode < 0)
		return errcode;

	payload = pt_read_value(decoder->pos + pt_opcs_tnt_64,
				pt_pl_tnt_64_size);

	bit_size = get_tnt_bit_size(payload);
	if (!bit_size)
		return -pte_bad_packet;

	/* Remove the stop bit from the payload. */
	payload &= ~(1ull << bit_size);

	packet->payload = payload;
	packet->bit_size = bit_size;

	return ptps_tnt_64;
}

static int packet_tnt_64(struct pt_packet *packet,
			 const struct pt_decoder *decoder)
{
	int size;

	size = extract_tnt_64(&packet->payload.tnt, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_64;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_tnt_64(struct pt_decoder *decoder)
{
	struct pt_packet_tnt packet;
	int size, errcode;

	size = extract_tnt_64(&packet, decoder);
	if (size < 0)
		return size;

	errcode = pt_tnt_cache_update_tnt(&decoder->tnt, &packet,
					  &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_tnt_64 = {
	/* .packet = */ packet_tnt_64,
	/* .decode = */ decode_tnt_64,
	/* .header = */ NULL,
	/* .flags = */ pdff_tnt
};

static int packet_tip_pge(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = extract_ip(&packet->payload.ip, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pge;
	packet->size = (uint8_t) size;

	return size;
}

static int consume_tip_pge(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

static int decode_tip_pge(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = decode_ip(decoder);
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
		ev = pt_standalone_event(decoder);
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
		ev = pt_dequeue_event(decoder, evb_tip);
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
				fill_in_event_ip(ev, &ev->variant.exec_mode.ip,
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
	if (pt_event_pending(decoder, evb_tip))
		return 0;

	/* We must consume the packet. */
	if (!(decoder->flags & pdf_consume_packet))
		return -pte_internal;

	decoder->flags &= ~pdf_consume_packet;

	return consume_tip_pge(decoder, size);
}

const struct pt_decoder_function pt_decode_tip_pge = {
	/* .packet = */ packet_tip_pge,
	/* .decode = */ decode_tip_pge,
	/* .header = */ NULL,
	/* .flags = */ pdff_event
};

static int packet_tip_pgd(struct pt_packet *packet,
			  const struct pt_decoder *decoder)
{
	int size;

	size = extract_ip(&packet->payload.ip, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pgd;
	packet->size = (uint8_t) size;

	return size;
}

static int consume_tip_pgd(struct pt_decoder *decoder, int size)
{
	decoder->flags |= pdf_pt_disabled;
	decoder->pos += size;
	return 0;
}

static int decode_tip_pgd(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	uint64_t at;
	int size;

	size = decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to TIP. */
	ev = pt_dequeue_event(decoder, evb_tip);
	if (ev) {
		/* The only event we expect is an async branch. */
		if (ev->type != ptev_async_branch)
			return -pte_internal;

		/* We do not expect any further events. */
		if (pt_event_pending(decoder, evb_tip))
			return -pte_internal;

		/* Turn the async branch into an async disable. */
		at = ev->variant.async_branch.from;

		ev->type = ptev_async_disabled;
		ev->variant.async_disabled.at = at;
		fill_in_event_ip(ev, &ev->variant.async_disabled.ip, decoder);
	} else {
		/* This packet signals a standalone disabled event. */
		ev = pt_standalone_event(decoder);
		if (!ev)
			return -pte_internal;
		ev->type = ptev_disabled;
		fill_in_event_ip(ev, &ev->variant.disabled.ip, decoder);
	}

	/* Publish the event. */
	decoder->event = ev;

	return consume_tip_pgd(decoder, size);
}

const struct pt_decoder_function pt_decode_tip_pgd = {
	/* .packet = */ packet_tip_pgd,
	/* .decode = */ decode_tip_pgd,
	/* .header = */ NULL,
	/* .flags = */ pdff_event
};

static int packet_fup(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_ip(&packet->payload.ip, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_fup;
	packet->size = (uint8_t) size;

	return size;
}

static int consume_fup(struct pt_decoder *decoder, int size)
{
	decoder->pos += size;
	return 0;
}

static int header_fup(struct pt_decoder *decoder)
{
	struct pt_packet_ip packet;
	int errcode, size;

	size = extract_ip(&packet, decoder);
	if (size < 0)
		return size;

	errcode = pt_last_ip_update_ip(&decoder->ip, &packet, &decoder->config);
	if (errcode < 0)
		return errcode;

	if (packet.ipc != pt_ipc_suppressed)
		decoder->flags |= pdf_status_have_ip;

	return consume_fup(decoder, size);
}

static int decode_fup(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	int size;

	size = decode_ip(decoder);
	if (size < 0)
		return size;

	/* Process any pending events binding to FUP. */
	ev = pt_dequeue_event(decoder, evb_fup);
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
			fill_in_event_ip(ev, &ev->variant.tsx.ip, decoder);

			/* A non-abort event will consume the packet. */
			if (!(ev->variant.tsx.aborted))
				decoder->flags |= pdf_consume_packet;

			break;
		}

		/* Publish the event. */
		decoder->event = ev;

		/* Process further pending events. */
		if (pt_event_pending(decoder, evb_fup))
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

		ev = pt_enqueue_event(decoder, evb_tip);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_async_branch;
		ev->variant.async_branch.from = ip;
	}

	return consume_fup(decoder, size);
}

const struct pt_decoder_function pt_decode_fup = {
	/* .packet = */ packet_fup,
	/* .decode = */ decode_fup,
	/* .header = */ header_fup,
	/* .flags = */ pdff_fup
};

static int extract_pip(struct pt_packet_pip *packet,
		       const struct pt_decoder *decoder)
{
	uint64_t payload;
	int errcode;

	errcode = pt_check_bounds(decoder, ptps_pip);
	if (errcode < 0)
		return errcode;

	/* Read the payload. */
	payload = pt_read_value(decoder->pos + pt_opcs_pip, pt_pl_pip_size);

	/* Create the cr3 value. */
	payload  >>= pt_pl_pip_shr;
	payload  <<= pt_pl_pip_shl;
	packet->cr3 = payload;

	return ptps_pip;
}

static int packet_pip(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_pip(&packet->payload.pip, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_pip;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_pip(struct pt_decoder *decoder)
{
	struct pt_packet_pip packet;
	struct pt_event *event;
	int size;

	size = extract_pip(&packet, decoder);
	if (size < 0)
		return size;

	/* Paging events are either standalone or bind to the same TIP packet
	 * as an in-flight async branch event.
	 */
	event = pt_find_event(decoder, ptev_async_branch, evb_tip);
	if (!event) {
		event = pt_standalone_event(decoder);
		if (!event)
			return -pte_internal;
		event->type = ptev_paging;
		event->variant.paging.cr3 = packet.cr3;

		decoder->event = event;
	} else {
		event = pt_enqueue_event(decoder, evb_tip);
		if (!event)
			return -pte_nomem;

		event->type = ptev_async_paging;
		event->variant.async_paging.cr3 = packet.cr3;
	}

	decoder->pos += size;
	return 0;
}

static int header_pip(struct pt_decoder *decoder)
{
	struct pt_packet_pip packet;
	struct pt_event *event;
	int size;

	size = extract_pip(&packet, decoder);
	if (size < 0)
		return size;

	/* Paging events are reported at the end of the PSB. */
	event = pt_enqueue_event(decoder, evb_psbend);
	if (!event)
		return -pte_nomem;

	event->type = ptev_paging;
	event->variant.paging.cr3 = packet.cr3;

	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_pip = {
	/* .packet = */ packet_pip,
	/* .decode = */ decode_pip,
	/* .header = */ header_pip,
	/* .flags = */ pdff_event
};

static int packet_ovf(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	packet->type = ppt_ovf;
	packet->size = ptps_ovf;

	return ptps_ovf;
}

static int prepare_psb_event(struct pt_event *ev)
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

static int process_pending_psb_events(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	ev = pt_dequeue_event(decoder, evb_psbend);
	if (!ev)
		return 0;

	errcode = prepare_psb_event(ev);
	if (errcode < 0)
		return errcode;

	switch (ev->type) {
	default:
		return -pte_internal;

	case ptev_async_paging:
		fill_in_event_ip(ev, &ev->variant.async_paging.ip, decoder);
		break;

	case ptev_exec_mode:
		fill_in_event_ip(ev, &ev->variant.exec_mode.ip, decoder);
		break;

	case ptev_tsx:
		fill_in_event_ip(ev, &ev->variant.tsx.ip, decoder);
		break;
	}

	/* Publish the event. */
	decoder->event = ev;

	/* Signal a pending event. */
	return 1;
}

static int decode_ovf(struct pt_decoder *decoder)
{
	struct pt_event *ev;
	uint64_t flags;
	int status;
	enum pt_event_binding evb;

	status = process_pending_psb_events(decoder);
	if (status < 0)
		return status;

	/* If we have any pending psbend events, we're done for now. */
	if (status)
		return 0;

	/* Reset the decoder state - but preserve some flags.
	 *
	 * We don't know how many packets we lost so any queued events or unused
	 * TNT bits will likely be wrong.
	 */
	flags = decoder->flags;

	pt_reset(decoder);

	decoder->flags |= flags & pdf_pt_disabled;

	/* OVF binds to FUP as long as tracing is enabled.
	 * It binds to TIP.PGE when tracing is disabled.
	 */
	evb = (flags & pdf_pt_disabled) ? evb_tip : evb_fup;

	/* Queue the overflow event.
	 *
	 * We must be able to enqueue the overflow event since we just reset
	 * the decoder state.
	 */
	ev = pt_enqueue_event(decoder, evb);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;

	decoder->pos += ptps_ovf;
	return 0;
}

const struct pt_decoder_function pt_decode_ovf = {
	/* .packet = */ packet_ovf,
	/* .decode = */ decode_ovf,
	/* .header = */ NULL,
	/* .flags = */ pdff_psbend
};

static int extract_mode_exec(struct pt_packet_mode_exec *packet, uint8_t mode)
{
	packet->csl = (mode & pt_mob_exec_csl) != 0;
	packet->csd = (mode & pt_mob_exec_csd) != 0;

	return ptps_mode;
}

static int extract_mode_tsx(struct pt_packet_mode_tsx *packet, uint8_t mode)
{
	packet->intx = (mode & pt_mob_tsx_intx) != 0;
	packet->abrt = (mode & pt_mob_tsx_abrt) != 0;

	return ptps_mode;
}

static int extract_mode(struct pt_packet_mode *packet,
			const struct pt_decoder *decoder)
{
	uint8_t payload, mode, leaf;
	int errcode;

	errcode = pt_check_bounds(decoder, ptps_mode);
	if (errcode < 0)
		return errcode;

	payload = decoder->pos[pt_opcs_mode];
	leaf = payload & pt_mom_leaf;
	mode = payload & pt_mom_bits;

	packet->leaf = (enum pt_mode_leaf) leaf;
	switch (leaf) {
	default:
		return -pte_bad_packet;

	case pt_mol_exec:
		return extract_mode_exec(&packet->bits.exec, mode);

	case pt_mol_tsx:
		return extract_mode_tsx(&packet->bits.tsx, mode);
	}
}

static int packet_mode(struct pt_packet *packet,
		       const struct pt_decoder *decoder)
{
	int size;

	size = extract_mode(&packet->payload.mode, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_mode;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_mode_exec(struct pt_decoder *decoder,
			    const struct pt_packet_mode_exec *packet)
{
	struct pt_event *event;

	/* MODE.EXEC binds to TIP. */
	event = pt_enqueue_event(decoder, evb_tip);
	if (!event)
		return -pte_nomem;

	event->type = ptev_exec_mode;
	event->variant.exec_mode.mode = pt_get_exec_mode(packet);

	return 0;
}

static int decode_mode_tsx(struct pt_decoder *decoder,
			   const struct pt_packet_mode_tsx *packet)
{
	struct pt_event *event;

	/* MODE.TSX is standalone if tracing is disabled. */
	if (decoder->flags & pdf_pt_disabled) {
		event = pt_standalone_event(decoder);
		if (!event)
			return -pte_internal;

		/* We don't have an IP in this case. */
		event->variant.tsx.ip = 0;
		event->ip_suppressed = 1;

		/* Publish the event. */
		decoder->event = event;
	} else {
		/* MODE.TSX binds to FUP. */
		event = pt_enqueue_event(decoder, evb_fup);
		if (!event)
			return -pte_nomem;
	}

	event->type = ptev_tsx;
	event->variant.tsx.speculative = packet->intx;
	event->variant.tsx.aborted = packet->abrt;

	return 0;
}

static int decode_mode(struct pt_decoder *decoder)
{
	struct pt_packet_mode packet;
	int size, errcode;

	size = extract_mode(&packet, decoder);
	if (size < 0)
		return size;

	errcode = 0;
	switch (packet.leaf) {
	case pt_mol_exec:
		errcode = decode_mode_exec(decoder, &packet.bits.exec);
		break;

	case pt_mol_tsx:
		errcode = decode_mode_tsx(decoder, &packet.bits.tsx);
		break;
	}

	if (errcode < 0)
		return errcode;

	decoder->pos += size;
	return 0;
}

static int header_mode(struct pt_decoder *decoder)
{
	struct pt_packet_mode packet;
	struct pt_event *event;
	int size;

	size = extract_mode(&packet, decoder);
	if (size < 0)
		return size;

	/* Inside the header, events are reported at the end. */
	event = pt_enqueue_event(decoder, evb_psbend);
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

const struct pt_decoder_function pt_decode_mode = {
	/* .packet = */ packet_mode,
	/* .decode = */ decode_mode,
	/* .header = */ header_mode,
	/* .flags = */ pdff_event
};

static int packet_psbend(struct pt_packet *packet,
			 const struct pt_decoder *decoder)
{
	packet->type = ppt_psbend;
	packet->size = ptps_psbend;

	return ptps_psbend;
}

static int decode_psbend(struct pt_decoder *decoder)
{
	int status;

	status = process_pending_psb_events(decoder);
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

const struct pt_decoder_function pt_decode_psbend = {
	/* .packet = */ packet_psbend,
	/* .decode = */ decode_psbend,
	/* .header = */ NULL,
	/* .flags = */ pdff_psbend
};

static int extract_tsc(struct pt_packet_tsc *packet,
		       const struct pt_decoder *decoder)
{
	int errcode;

	errcode = pt_check_bounds(decoder, ptps_tsc);
	if (errcode < 0)
		return errcode;

	packet->tsc = pt_read_value(decoder->pos + pt_opcs_tsc, pt_pl_tsc_size);

	return ptps_tsc;
}

static int packet_tsc(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_tsc(&packet->payload.tsc, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_tsc;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_tsc(struct pt_decoder *decoder)
{
	struct pt_packet_tsc packet;
	int size;

	size = extract_tsc(&packet, decoder);
	if (size < 0)
		return size;

	decoder->tsc = packet.tsc;
	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_tsc = {
	/* .packet = */ packet_tsc,
	/* .decode = */ decode_tsc,
	/* .header = */ decode_tsc,
	/* .flags = */ 0
};

static int extract_cbr(struct pt_packet_cbr *packet,
		       const struct pt_decoder *decoder)
{
	const uint8_t *pos;
	int errcode;

	pos = decoder->pos;

	errcode = pt_check_bounds(decoder, ptps_cbr);
	if (errcode < 0)
		return errcode;

	packet->ratio = pos[2];

	return ptps_cbr;
}

static int packet_cbr(struct pt_packet *packet,
		      const struct pt_decoder *decoder)
{
	int size;

	size = extract_cbr(&packet->payload.cbr, decoder);
	if (size < 0)
		return size;

	packet->type = ppt_cbr;
	packet->size = (uint8_t) size;

	return size;
}

static int decode_cbr(struct pt_decoder *decoder)
{
	struct pt_packet_cbr packet;
	int size;

	size = extract_cbr(&packet, decoder);
	if (size < 0)
		return size;

	decoder->pos += size;
	return 0;
}

const struct pt_decoder_function pt_decode_cbr = {
	/* .packet = */ packet_cbr,
	/* .decode = */ decode_cbr,
	/* .header = */ decode_cbr,
	/* .flags = */ 0
};

int pt_fetch_decoder(struct pt_decoder *decoder)
{
	const uint8_t *pos, *begin, *end;
	uint8_t opc, ext;

	if (!decoder)
		return -pte_internal;

	/* Clear the decoder's decode function in case of errors. */
	decoder->next = NULL;

	begin = pt_begin(decoder);
	end = pt_end(decoder);
	pos = decoder->pos;

	if (!pos || (pos < begin) || (end < pos))
		return -pte_nosync;

	if (pos == end)
		return -pte_eos;

	opc = *pos++;
	switch (opc) {
	default:
		/* Check opcodes that require masking. */
		if ((opc & pt_opm_tnt_8) == pt_opc_tnt_8) {
			decoder->next = &pt_decode_tnt_8;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip) {
			decoder->next = &pt_decode_tip;
			return 0;
		}

		if ((opc & pt_opm_fup) == pt_opc_fup) {
			decoder->next = &pt_decode_fup;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip_pge) {
			decoder->next = &pt_decode_tip_pge;
			return 0;
		}

		if ((opc & pt_opm_tip) == pt_opc_tip_pgd) {
			decoder->next = &pt_decode_tip_pgd;
			return 0;
		}

		decoder->next = &pt_decode_unknown;
		return 0;

	case pt_opc_pad:
		decoder->next = &pt_decode_pad;
		return 0;

	case pt_opc_mode:
		decoder->next = &pt_decode_mode;
		return 0;

	case pt_opc_tsc:
		decoder->next = &pt_decode_tsc;
		return 0;

	case pt_opc_ext:
		if (pos == end)
			return -pte_eos;

		ext = *pos++;
		switch (ext) {
		default:
			decoder->next = &pt_decode_unknown;
			return 0;

		case pt_ext_psb:
			decoder->next = &pt_decode_psb;
			return 0;

		case pt_ext_ovf:
			decoder->next = &pt_decode_ovf;
			return 0;

		case pt_ext_tnt_64:
			decoder->next = &pt_decode_tnt_64;
			return 0;

		case pt_ext_psbend:
			decoder->next = &pt_decode_psbend;
			return 0;

		case pt_ext_cbr:
			decoder->next = &pt_decode_cbr;
			return 0;

		case pt_ext_pip:
			decoder->next = &pt_decode_pip;
			return 0;
		}
	}
}
