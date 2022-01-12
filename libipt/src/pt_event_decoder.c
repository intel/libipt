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

#include "pt_event_decoder.h"
#include "pt_compiler.h"
#include "pt_opcodes.h"
#include "pt_config.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>


/* Initialize the packet decoder flags based on our flags. */

static int pt_evt_init_pkt_flags(struct pt_conf_flags *pflags,
				 const struct pt_conf_flags *flags)
{
	if (!pflags || !flags)
		return -pte_internal;

	memset(pflags, 0, sizeof(*pflags));

	return 0;
}

static int pt_evt_reset(struct pt_event_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->packet.type = ppt_invalid;
	decoder->status = -pte_nosync;
	decoder->event = NULL;
	decoder->enabled = 0;
	decoder->bound = 0;

	pt_last_ip_init(&decoder->ip);
	pt_time_init(&decoder->time);
	pt_tcal_init(&decoder->tcal);
	pt_evq_init(&decoder->evq);

	return 0;
}

int pt_evt_decoder_init(struct pt_event_decoder *decoder,
			const struct pt_config *uconfig)
{
	struct pt_config config;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_config_from_user(&config, uconfig);
	if (errcode < 0)
		return errcode;

	/* The user supplied decoder flags. */
	decoder->flags = config.flags;

	/* Set the flags we need for the packet decoder we use. */
	errcode = pt_evt_init_pkt_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_decoder_init(&decoder->pacdec, &config);
	if (errcode < 0)
		return errcode;

	return pt_evt_reset(decoder);
}

void pt_evt_decoder_fini(struct pt_event_decoder *decoder)
{
	if (!decoder)
		return;

	pt_pkt_decoder_fini(&decoder->pacdec);
}

struct pt_event_decoder *pt_evt_alloc_decoder(const struct pt_config *config)
{
	struct pt_event_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_evt_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_evt_free_decoder(struct pt_event_decoder *decoder)
{
	if (!decoder)
		return;

	pt_evt_decoder_fini(decoder);
	free(decoder);
}

/* Fetch the next packet and return zero.
 *
 * Fetch the next packet using the packet decoder and store away any error
 * return for later.
 *
 * Can be used to return from a packet decode function to indicate that the
 * current packet has been processed completely and resulted in an event.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_evt_fetch_packet(struct pt_event_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_internal;

	/* Skip PAD packets right here.
	 *
	 * This isn't strictly necessary but it gives more useful offsets.
	 */
	do {
		status = pt_pkt_next(&decoder->pacdec, &decoder->packet,
				     sizeof(decoder->packet));
		if (status < 0) {
			/* Store any error to be delivered later. */
			decoder->packet.type = ppt_invalid;
			decoder->packet.size = 0;
			decoder->status = status;

			break;
		}
	} while (decoder->packet.type == ppt_pad);

	return 0;
}

static int pt_evt_event_time(struct pt_event *ev, const struct pt_time *time)
{
	int errcode;

	if (!ev || !time)
		return -pte_internal;

	errcode = pt_time_query_tsc(&ev->tsc, &ev->lost_mtc, &ev->lost_cyc,
				    time);
	if (errcode < 0) {
		if (errcode != -pte_no_time)
			return errcode;
	} else
		ev->has_tsc = 1;

	return 0;
}

static int pt_evt_event_ip(uint64_t *ip, struct pt_event *ev,
			   const struct pt_last_ip *last_ip)
{
	int errcode;

	if (!ev)
		return -pte_internal;

	errcode = pt_last_ip_query(ip, last_ip);
	if (errcode < 0) {
		switch (pt_errcode(errcode)) {
		case pte_noip:
		case pte_ip_suppressed:
			ev->ip_suppressed = 1;
			break;

		default:
			return errcode;
		}
	}

	return 0;
}

/* Find a FUP in a PSB+ header.
 *
 * @pacdec must be synchronized onto the trace stream at the beginning or
 * somewhere inside a PSB+ header.
 *
 * @packet holds trace packets during the search.  If the search is successful,
 * @packet will contain the first (and hopefully only) FUP packet in this PSB+.
 * Otherwise, @packet may contain anything.
 *
 * Returns one if a FUP packet is found (@packet will contain it).
 * Returns zero if no FUP packet is found (@packet is undefined).
 * Returns a negative error code otherwise.
 */
static int pt_evt_find_header_fup(struct pt_packet *packet,
				  const struct pt_packet_decoder *pacdec)
{
	struct pt_packet_decoder decoder;

	if (!packet || !pacdec)
		return -pte_internal;

	decoder = *pacdec;
	for (;;) {
		int errcode;

		errcode = pt_pkt_next(&decoder, packet, sizeof(*packet));
		if (errcode < 0)
			return errcode;

		switch (packet->type) {
		case ppt_fup:
			/* Found it. */
			return 1;

		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_mnt:
		case ppt_tsc:
		case ppt_cbr:
		case ppt_tma:
		case ppt_mtc:
		case ppt_cyc:
		case ppt_pad:
		case ppt_invalid:
			/* Ignore the packet. */
			break;

		case ppt_psbend:
		case ppt_ovf:
			/* There's no FUP in here. */
			return 0;

		default:
			return -pte_bad_context;
		}
	}
}

static int pt_evt_apply_header_tsc(struct pt_time *time,
				   struct pt_time_cal *tcal,
				   const struct pt_packet_tsc *packet,
				   const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_header_tsc(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tsc(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_header_tsc(struct pt_event_decoder *decoder,
			     const struct pt_packet_tsc *packet)
{
	return pt_evt_apply_header_tsc(&decoder->time, &decoder->tcal, packet,
				       pt_evt_config(decoder));
}

static int pt_evt_apply_tsc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_tsc *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_update_tsc(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tsc(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_decode_tsc(struct pt_event_decoder *decoder,
			     const struct pt_packet_tsc *packet)
{
	int errcode;

	errcode = pt_evt_apply_tsc(&decoder->time, &decoder->tcal, packet,
				   pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	return 1;
}

static int pt_evt_apply_header_cbr(struct pt_time *time,
				   struct pt_time_cal *tcal,
				   const struct pt_packet_cbr *packet,
				   const struct pt_config *config)
{
	int errcode;

	if (!packet)
		return -pte_internal;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_header_cbr(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_cbr(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_header_cbr(struct pt_event_decoder *decoder,
			     const struct pt_packet_cbr *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_evt_apply_header_cbr(&decoder->time, &decoder->tcal,
					  packet, pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->status_update = 1;
	ev->type = ptev_cbr;
	ev->variant.cbr.ratio = packet->ratio;

	return 0;
}

static int pt_evt_apply_cbr(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_cbr *packet,
			    const struct pt_config *config)
{
	int errcode;

	if (!packet)
		return -pte_internal;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_update_cbr(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_cbr(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_decode_cbr(struct pt_event_decoder *decoder,
			     const struct pt_packet_cbr *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_evt_apply_cbr(&decoder->time, &decoder->tcal, packet,
				   pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_cbr;
	ev->variant.cbr.ratio = packet->ratio;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_apply_tma(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_tma *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_update_tma(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_tma(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_header_tma(struct pt_event_decoder *decoder,
			     const struct pt_packet_tma *packet)
{
	return pt_evt_apply_tma(&decoder->time, &decoder->tcal, packet,
				pt_evt_config(decoder));
}

static int pt_evt_decode_tma(struct pt_event_decoder *decoder,
			     const struct pt_packet_tma *packet)
{
	int errcode;

	errcode = pt_evt_apply_tma(&decoder->time, &decoder->tcal, packet,
				   pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	return 1;
}

static int pt_evt_apply_mtc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_mtc *packet,
			    const struct pt_config *config)
{
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_update_mtc(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * timing and are tracked as packet losses in struct pt_time.
	 */
	errcode = pt_time_update_mtc(time, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_header_mtc(struct pt_event_decoder *decoder,
			     const struct pt_packet_mtc *packet)
{
	return pt_evt_apply_mtc(&decoder->time, &decoder->tcal, packet,
				pt_evt_config(decoder));
}

static int pt_evt_decode_mtc(struct pt_event_decoder *decoder,
			     const struct pt_packet_mtc *packet)
{
	int errcode;

	errcode = pt_evt_apply_mtc(&decoder->time, &decoder->tcal, packet,
				   pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	return 1;
}

static int pt_evt_apply_cyc(struct pt_time *time, struct pt_time_cal *tcal,
			    const struct pt_packet_cyc *packet,
			    const struct pt_config *config)
{
	uint64_t fcr;
	int errcode;

	/* We ignore configuration errors.  They will result in imprecise
	 * calibration which will result in imprecise cycle-accurate timing.
	 */
	errcode = pt_tcal_update_cyc(tcal, packet, config);
	if ((errcode < 0) && (errcode != -pte_bad_config))
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
	if ((errcode < 0) && (errcode != -pte_bad_config))
		return errcode;

	return 0;
}

static int pt_evt_header_cyc(struct pt_event_decoder *decoder,
			     const struct pt_packet_cyc *packet)
{
	return pt_evt_apply_cyc(&decoder->time, &decoder->tcal, packet,
				pt_evt_config(decoder));
}

static int pt_evt_decode_cyc(struct pt_event_decoder *decoder,
			     const struct pt_packet_cyc *packet)
{
	int errcode;

	errcode = pt_evt_apply_cyc(&decoder->time, &decoder->tcal, packet,
				   pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	return 1;
}

static int pt_evt_check_bdm70(struct pt_event_decoder *decoder)
{
	struct pt_packet_decoder pacdec;

	if (!decoder)
		return -pte_internal;

	pacdec = decoder->pacdec;
	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(&pacdec, &packet, sizeof(packet));
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
			 * We do not enumerate those packets since we also want
			 * to include new packets.
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
			break;
		}
	}
}

static int pt_evt_header_fup(struct pt_event_decoder *decoder,
			     const struct pt_packet_ip *packet)
{
	const struct pt_config *config;
	unsigned int enabled;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	enabled = (packet->ipc != pt_ipc_suppressed);

	config = pt_evt_config(decoder);
	if (!config)
		return -pte_internal;

	if (config->errata.bdm70) {
		errcode = pt_evt_check_bdm70(decoder);
		if (errcode < 0)
			return errcode;

		if (errcode)
			enabled = 0;
	}

	decoder->enabled = enabled;
	if (!enabled)
		return 0;

	return pt_last_ip_update_ip(&decoder->ip, packet, config);
}

static int pt_evt_header_mode(struct pt_event_decoder *decoder,
			      const struct pt_packet_mode *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->status_update = 1;
	switch (packet->leaf) {
	case pt_mol_exec:
		ev->type = ptev_exec_mode;
		ev->variant.exec_mode.mode =
			pt_get_exec_mode(&packet->bits.exec);
		break;

	case pt_mol_tsx:
		ev->type = ptev_tsx;
		ev->variant.tsx.speculative = packet->bits.tsx.intx;
		ev->variant.tsx.aborted = packet->bits.tsx.abrt;
		break;
	}

	return 0;
}

static int pt_evt_decode_mode_exec(struct pt_event_decoder *decoder,
				   const struct pt_packet_mode_exec *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_tip);
	if (!ev)
		return -pte_nomem;

	ev->type = ptev_exec_mode;
	ev->variant.exec_mode.mode = pt_get_exec_mode(packet);

	return 1;
}

static int pt_evt_decode_mode_tsx(struct pt_event_decoder *decoder,
				  const struct pt_packet_mode_tsx *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	if (decoder->enabled) {
		ev = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_tsx;
		ev->variant.tsx.speculative = packet->intx;
		ev->variant.tsx.aborted = packet->abrt;

		return 1;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_tsx;
	ev->variant.tsx.speculative = packet->intx;
	ev->variant.tsx.aborted = packet->abrt;

	ev->variant.tsx.ip = 0ull;
	ev->ip_suppressed = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_mode(struct pt_event_decoder *decoder,
			      const struct pt_packet_mode *packet)
{
	if (!packet)
		return -pte_internal;

	switch (packet->leaf) {
	case pt_mol_exec:
		return pt_evt_decode_mode_exec(decoder,
					       &packet->bits.exec);

	case pt_mol_tsx:
		return pt_evt_decode_mode_tsx(decoder,
					      &packet->bits.tsx);
	}

	return -pte_bad_opc;
}

static int pt_evt_header_pip(struct pt_event_decoder *decoder,
			     const struct pt_packet_pip *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->status_update = 1;
	ev->type = ptev_async_paging;
	ev->variant.async_paging.cr3 = packet->cr3;
	ev->variant.async_paging.non_root = packet->nr;

	return 0;
}

static int pt_evt_decode_pip(struct pt_event_decoder *decoder,
			     const struct pt_packet_pip *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	/* PIP is standalone or binds to the same TIP as an unbound FUP.
	 *
	 * That unbound FUP will queue an async branch event at TIP.  Let's
	 * search for that.
	 */
	ev = pt_evq_find(&decoder->evq, evb_tip, ptev_async_branch);
	if (ev) {
		ev = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_async_paging;
		ev->variant.async_paging.cr3 = packet->cr3;
		ev->variant.async_paging.non_root = packet->nr;

		return 1;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_paging;
	ev->variant.paging.cr3 = packet->cr3;
	ev->variant.paging.non_root = packet->nr;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_header_vmcs(struct pt_event_decoder *decoder,
			      const struct pt_packet_vmcs *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->status_update = 1;
	ev->type = ptev_async_vmcs;
	ev->variant.async_vmcs.base = packet->base;

	return 0;
}

static int pt_evt_decode_vmcs(struct pt_event_decoder *decoder,
			      const struct pt_packet_vmcs *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	/* When getting both PIP and VMCS between the FUP and TIP of an
	 * asynchronous branch, we order VMCS before PIP.
	 *
	 * A preceding PIP will queue an async paging event.  Let's search for
	 * it.  When we find one, we re-purpose that event slot to hold the
	 * VMCS and add nother entry for the original async paging event.
	 */
	ev = pt_evq_find(&decoder->evq, evb_tip, ptev_async_paging);
	if (ev) {
		struct pt_event *paging;

		paging = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!paging)
			return -pte_nomem;

		*paging = *ev;

		ev->type = ptev_async_vmcs;
		ev->variant.async_vmcs.base = packet->base;

		return 1;
	}

	/* VMCS is standalone or binds to the same TIP as an unbound FUP.
	 *
	 * That unbound FUP will queue an async branch event at TIP.  Let's
	 * search for that.
	 *
	 * A standalone VMCS will bind to a VMPTRLD, VMRESUME, or VMLAUNCH
	 * instruction and will have to be bound by a higher-layer decoder.
	 */
	ev = pt_evq_find(&decoder->evq, evb_tip, ptev_async_branch);
	if (ev) {
		ev = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_async_vmcs;
		ev->variant.async_vmcs.base = packet->base;

		return 1;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_vmcs;
	ev->variant.vmcs.base = packet->base;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_header_mnt(struct pt_event_decoder *decoder,
			      const struct pt_packet_mnt *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->type = ptev_mnt;
	ev->variant.mnt.payload = packet->payload;

	return 0;
}

static int pt_evt_decode_mnt(struct pt_event_decoder *decoder,
			      const struct pt_packet_mnt *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_mnt;
	ev->variant.mnt.payload = packet->payload;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_stop(struct pt_event_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_stop;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_exstop(struct pt_event_decoder *decoder,
				const struct pt_packet_exstop *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_dequeue(&decoder->evq, evb_exstop);
	if (ev) {
		switch (ev->type) {
		case ptev_mwait:
			/* If we have an IP, both MWAIT and EXSTOP bind to the
			 * same IP.
			 *
			 * Let's enqueue MWAIT; we'll enqueue EXSTOP below, as
			 * well, unless we have further events pending.  In
			 * that case, enqueing EXSTOP will have to wait.
			 */
			if (packet->ip) {
				struct pt_event *mwait;

				mwait = pt_evq_enqueue(&decoder->evq, evb_fup);
				if (!mwait)
					return -pte_nomem;

				*mwait = *ev;
				break;
			}

			/* If we do not have an IP, both MWAIT and EXSTOP are
			 * standalone.
			 *
			 * Let's publish the MWAIT; on the next call, we'll
			 * publish the EXSTOP.
			 */
			ev->variant.mwait.ip = 0ull;
			ev->ip_suppressed = 1;

			decoder->event = ev;

			return pt_evt_event_time(ev, &decoder->time);

		default:
			return -pte_internal;
		}
	}

	/* If EXSTOP.IP is set, it binds to a subsequent FUP. */
	if (packet->ip) {
		ev = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_exstop;

		return 1;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_exstop;

	ev->variant.exstop.ip = 0ull;
	ev->ip_suppressed = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_mwait(struct pt_event_decoder *decoder,
			       const struct pt_packet_mwait *packet)
{
	struct pt_event *ev;

	if (!decoder || !packet)
		return -pte_internal;

	ev = pt_evq_enqueue(&decoder->evq, evb_exstop);
	if (!ev)
		return -pte_nomem;

	ev->type = ptev_mwait;
	ev->variant.mwait.hints = packet->hints;
	ev->variant.mwait.ext = packet->ext;

	return 1;
}

static int pt_evt_decode_pwre(struct pt_event_decoder *decoder,
			      const struct pt_packet_pwre *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_pwre;
	ev->variant.pwre.state = packet->state;
	ev->variant.pwre.sub_state = packet->sub_state;

	if (packet->hw)
		ev->variant.pwre.hw = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_pwrx(struct pt_event_decoder *decoder,
			      const struct pt_packet_pwrx *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_pwrx;
	ev->variant.pwrx.last = packet->last;
	ev->variant.pwrx.deepest = packet->deepest;

	if (packet->interrupt)
		ev->variant.pwrx.interrupt = 1;
	if (packet->store)
		ev->variant.pwrx.store = 1;
	if (packet->autonomous)
		ev->variant.pwrx.autonomous = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_ptw(struct pt_event_decoder *decoder,
			     const struct pt_packet_ptw *packet)
{
	struct pt_event *ev;
	int errcode, size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_ptw_size(packet->plc);
	if (size < 0)
		return size;

	/* If PTW.IP is set, it binds to a subsequent FUP. */
	if (packet->ip) {
		ev = pt_evq_enqueue(&decoder->evq, evb_fup);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_ptwrite;
		ev->variant.ptwrite.size = (uint8_t) size;
		ev->variant.ptwrite.payload = packet->payload;

		return 1;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_ptwrite;
	ev->variant.ptwrite.size = (uint8_t) size;
	ev->variant.ptwrite.payload = packet->payload;

	ev->variant.ptwrite.ip = 0ull;
	ev->ip_suppressed = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

/* Decode packets in the PSB+ header.
 *
 * Packets in PSB+ give the current state.  When starting to decode, they can
 * be used to initialize a decoder's state.  When encountered during decode,
 * they can be used to check the decoder's state for consistency.
 *
 * Inside PSB+ packets observe different binding rules.  The order in which
 * packets appear in PSB+ is undefined.  We model this by binding all packets
 * to PSBEND (or OVF in its place).
 *
 * By then, we should have gotten the current IP and TSC, so we can use them
 * when reporting PSB+ events.  We mark all PSB+ events as status events.
 *
 * Header packet decode functions return:
 *
 *    zero.......the packet was processed successfully
 *    negative...an error occurred during packet processing
 *
 * They are not required or expected to fetch the next packet.  This will be
 * done by this functions.
 *
 * Returns one on success, a negative pt_error_code otherwise.
 */
static int pt_evt_decode_psb(struct pt_event_decoder *decoder)
{
	const struct pt_packet *packet;
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	/* We must not carry partial events across PSB. */
	if (!pt_evq_empty(&decoder->evq, evb_psbend) ||
	    !pt_evq_empty(&decoder->evq, evb_tip) ||
	    !pt_evq_empty(&decoder->evq, evb_fup))
		return -pte_bad_context;

	pt_last_ip_init(&decoder->ip);
	decoder->enabled = 0;

	/* Create an event that will represent the enabled/disabled status.
	 *
	 * We do not know the status, yet, but we want the event to be first.
	 * We will fill in the details when we reach PSBEND.
	 */
	ev = pt_evq_enqueue(&decoder->evq, evb_psbend);
	if (!ev)
		return -pte_nomem;

	ev->status_update = 1;

	packet = &decoder->packet;
	for (;;) {
		errcode = pt_evt_fetch_packet(decoder);
		if (errcode < 0)
			return errcode;

		switch (packet->type) {
		case ppt_fup:
			errcode = pt_evt_header_fup(decoder,
						    &packet->payload.ip);
			break;

		case ppt_mode:
			errcode = pt_evt_header_mode(decoder,
						     &packet->payload.mode);
			break;

		case ppt_pip:
			errcode = pt_evt_header_pip(decoder,
						    &packet->payload.pip);
			break;

		case ppt_vmcs:
			errcode = pt_evt_header_vmcs(decoder,
						     &packet->payload.vmcs);
			break;

		case ppt_mnt:
			errcode = pt_evt_header_mnt(decoder,
						    &packet->payload.mnt);
			break;

		case ppt_tsc:
			errcode = pt_evt_header_tsc(decoder,
						    &packet->payload.tsc);
			break;

		case ppt_cbr:
			errcode = pt_evt_header_cbr(decoder,
						    &packet->payload.cbr);
			break;

		case ppt_tma:
			errcode = pt_evt_header_tma(decoder,
						    &packet->payload.tma);
			break;

		case ppt_mtc:
			errcode = pt_evt_header_mtc(decoder,
						    &packet->payload.mtc);
			break;

		case ppt_cyc:
			errcode = pt_evt_header_cyc(decoder,
						    &packet->payload.cyc);
			break;

		case ppt_psbend:
			if (decoder->enabled)
				ev->type = ptev_enabled;
			else {
				ev->type = ptev_disabled;
				ev->ip_suppressed = 1;
			}

			return 1;

		case ppt_ovf: {
			/* When PSB+ ends with an OVF, we remove the event we
			 * created initially if tracing is not enabled.
			 *
			 * We may have lost the FUP and end up with an invalid
			 * status update that might be diagnosed before we
			 * reach the overflow event.
			 */
			if (decoder->enabled)
				ev->type = ptev_enabled;
			else {
				const struct pt_event *head;

				head = pt_evq_dequeue(&decoder->evq,
						      evb_psbend);
				if (head != ev)
					return -pte_internal;
			}

			return 1;
		}

		case ppt_pad:
			break;

		case ppt_invalid:
			errcode = decoder->status;
			break;

		default:
			errcode = -pte_bad_context;
			break;
		}

		if (errcode < 0)
			return errcode;
	}
}

static int pt_evt_start(struct pt_event_decoder *decoder)
{
	int errcode;

	if (!decoder)
		return -pte_internal;

	decoder->status = 0;

	errcode = pt_evt_fetch_packet(decoder);
	if (errcode < 0)
		return errcode;

	switch (decoder->packet.type) {
	case ppt_psb:
		errcode = pt_evt_decode_psb(decoder);
		if (errcode < 0)
			return errcode;

		return 0;

	case ppt_invalid:
		/* We should have an error. */
		errcode = decoder->status;
		if (0 <= errcode)
			errcode = -pte_internal;

		return errcode;

	default:
		return -pte_nosync;
	}
}

static int pt_evt_sync_reset(struct pt_event_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	return pt_evt_reset(decoder);
}

int pt_evt_sync_forward(struct pt_event_decoder *decoder)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_evt_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_forward(&decoder->pacdec);
	if (errcode < 0)
		return errcode;

	return pt_evt_start(decoder);
}

int pt_evt_sync_backward(struct pt_event_decoder *decoder)
{
	const uint8_t *start, *sync, *pos;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	start = pt_evt_pos(decoder);
	if (!start) {
		start = pt_evt_end(decoder);
		if (!start)
			return -pte_bad_config;
	}

	sync = start;
	for (;;) {
		errcode = pt_evt_sync_reset(decoder);
		if (errcode < 0)
			return errcode;

		do {
			errcode = pt_pkt_sync_backward(&decoder->pacdec);
			if (errcode < 0)
				return errcode;

			pos = pt_evt_pos(decoder);
		} while (sync <= pos);

		sync = pos;

		errcode = pt_evt_start(decoder);

		pos = pt_evt_pos(decoder);
		if (pos < start)
			return errcode;
	}
}

int pt_evt_sync_set(struct pt_event_decoder *decoder, uint64_t offset)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_evt_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_set(&decoder->pacdec, offset);
	if (errcode < 0)
		return errcode;

	return pt_evt_start(decoder);
}

int pt_evt_get_offset(const struct pt_event_decoder *decoder, uint64_t *offset)
{
	uint64_t pktoff;
	int errcode;

	if (!decoder || !offset)
		return -pte_invalid;

	errcode = pt_pkt_get_offset(&decoder->pacdec, &pktoff);
	if (errcode < 0)
		return errcode;

	*offset = pktoff - decoder->packet.size;

	return 0;
}

int pt_evt_get_sync_offset(const struct pt_event_decoder *decoder,
			   uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_pkt_get_sync_offset(&decoder->pacdec, offset);
}

const struct pt_config *
pt_evt_get_config(const struct pt_event_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_pkt_get_config(&decoder->pacdec);
}

static int pt_evt_decode_psbend(struct pt_event_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	ev = pt_evq_dequeue(&decoder->evq, evb_psbend);
	if (!ev)
		return 1;

	decoder->event = ev;

	switch (ev->type) {
	case ptev_enabled:
		errcode = pt_evt_event_ip(&ev->variant.enabled.ip, ev,
					  &decoder->ip);
		break;

	case ptev_exec_mode:
		errcode = pt_evt_event_ip(&ev->variant.exec_mode.ip, ev,
					  &decoder->ip);
		break;

	case ptev_tsx:
		errcode = pt_evt_event_ip(&ev->variant.tsx.ip, ev,
					  &decoder->ip);
		break;

	case ptev_async_paging:
		errcode = pt_evt_event_ip(&ev->variant.async_paging.ip, ev,
					  &decoder->ip);
		break;

	case ptev_async_vmcs:
		errcode = pt_evt_event_ip(&ev->variant.async_vmcs.ip, ev,
					  &decoder->ip);
		break;

	case ptev_disabled:
	case ptev_cbr:
	case ptev_mnt:
		errcode = 0;
		break;

	default:
		errcode = -pte_bad_context;
		break;
	}

	if (errcode < 0)
		return errcode;

	return pt_evt_event_time(ev, &decoder->time);
}

static int pt_evt_decode_fup(struct pt_event_decoder *decoder,
			     const struct pt_packet_ip *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	errcode = pt_last_ip_update_ip(&decoder->ip, packet,
				       pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	ev = pt_evq_dequeue(&decoder->evq, evb_fup);
	if (!ev) {
		uint64_t from;

		if (decoder->bound)
			return 1;

		/* We must have a from IP for asynchronous branches.
		 *
		 * The event's ip_suppressed field only applies to the to field
		 * so we cannot really express a suppressed from IP and leave
		 * it to our users to diagnose.
		 *
		 * Since this case isn't allowed, anyway, we diagnose it here.
		 */
		errcode = pt_last_ip_query(&from, &decoder->ip);
		if (errcode < 0)
			return errcode;

		ev = pt_evq_enqueue(&decoder->evq, evb_tip);
		if (!ev)
			return -pte_nomem;

		ev->type = ptev_async_branch;
		ev->variant.async_branch.from = from;

		return 1;
	}

	decoder->event = ev;

	switch (ev->type) {
	case ptev_overflow:
		/* We preserve the time at the OVF.
		 *
		 * This may give an indication as to how long the overflow
		 * lasted when comparing it with the time at the next event.
		 */
		errcode = pt_evt_event_ip(&ev->variant.overflow.ip, ev,
					  &decoder->ip);

		decoder->enabled = 1;
		decoder->bound = 1;
		break;

	case ptev_tsx:
		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			break;

		errcode = pt_evt_event_ip(&ev->variant.tsx.ip, ev,
					  &decoder->ip);

		if (!(ev->variant.tsx.aborted))
			decoder->bound = 1;

		break;

	case ptev_exstop:
		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			break;

		errcode = pt_evt_event_ip(&ev->variant.exstop.ip, ev,
					  &decoder->ip);

		decoder->bound = 1;
		break;

	case ptev_mwait:
		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			break;

		errcode = pt_evt_event_ip(&ev->variant.mwait.ip, ev,
					  &decoder->ip);

		decoder->bound = 1;
		break;

	case ptev_ptwrite:
		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			break;

		errcode = pt_evt_event_ip(&ev->variant.ptwrite.ip, ev,
					  &decoder->ip);

		decoder->bound = 1;
		break;

	default:
		errcode = -pte_bad_context;
		break;
	}

	if (errcode < 0)
		return errcode;

	return 0;
}

/* Search for a FUP or a non-PacketEn packet starting at @pacdec.
 *
 * Returns a positive offset to (one byte after) the found FUP packet.
 * Returns zero if a non-PacketEn packet is found.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_evt_find_ovf_fup(const struct pt_packet_decoder *pacdec)
{
	struct pt_packet_decoder decoder;
	int offset;

	if (!pacdec)
		return -pte_internal;

	decoder = *pacdec;
	offset = 0;
	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(&decoder, &packet, sizeof(packet));
		if (errcode < 0)
			return errcode;

		if (!packet.size)
			return -pte_bad_packet;

		offset += packet.size;
		if (offset < 0)
			return -pte_overflow;

		switch (packet.type) {
		case ppt_fup:
			return offset;

		case ppt_unknown:
		case ppt_pad:
		case ppt_mnt:
		case ppt_cbr:
		case ppt_tsc:
		case ppt_tma:
		case ppt_mtc:
		case ppt_cyc:
		case ppt_invalid:
			break;

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

static int pt_evt_recover_ovf_at_ip(struct pt_event_decoder *decoder,
				    const struct pt_packet_decoder *pacdec,
				    const struct pt_packet *packet,
				    const struct pt_packet_ip *ip,
				    const struct pt_time *time,
				    const struct pt_time_cal *tcal)
{
	const struct pt_config *config;
	struct pt_event *ev;
	int errcode;

	if (!decoder || !pacdec || !packet || !time || !tcal)
		return -pte_internal;

	config = pt_evt_config(decoder);

	errcode = pt_last_ip_update_ip(&decoder->ip, ip, config);
	if (errcode < 0)
		return errcode;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;

	/* We use the decoder's original time for this event. */
	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	decoder->pacdec = *pacdec;
	decoder->packet = *packet;
	decoder->time = *time;
	decoder->tcal = *tcal;
	decoder->enabled = 1;

	return pt_evt_event_ip(&ev->variant.overflow.ip, ev, &decoder->ip);
}

static int pt_evt_recover_ovf_disabled(struct pt_event_decoder *decoder,
				       const struct pt_packet_decoder *pacdec,
				       const struct pt_packet *packet,
				       const struct pt_time *time,
				       const struct pt_time_cal *tcal)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !pacdec || !packet || !time || !tcal)
		return -pte_internal;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;
	ev->ip_suppressed = 1;

	/* We use the decoder's original time for this event. */
	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	decoder->pacdec = *pacdec;
	decoder->packet = *packet;
	decoder->time = *time;
	decoder->tcal = *tcal;

	return 0;
}

static int pt_evt_recover_ovf_at_offset(struct pt_event_decoder *decoder,
					uint64_t offset)
{
	const struct pt_packet *packet;
	struct pt_event *ev;
	int errcode;

	if (!decoder || !offset)
		return -pte_internal;

	packet = &decoder->packet;
	for (;;) {
		errcode = pt_pkt_next(&decoder->pacdec, &decoder->packet,
				      sizeof(decoder->packet));
		if (errcode < 0)
			return errcode;

		if (offset <= packet->size) {
			if (offset < packet->size)
				return -pte_internal;

			break;
		}

		offset -= packet->size;

		switch (packet->type) {
		case ppt_tsc:
			/* Keep track of time. */
			errcode = pt_evt_apply_tsc(&decoder->time,
						   &decoder->tcal,
						   &packet->payload.tsc,
						   pt_evt_config(decoder));
			break;

		case ppt_cbr:
			/* Keep track of time. */
			errcode = pt_evt_apply_cbr(&decoder->time,
						   &decoder->tcal,
						   &packet->payload.cbr,
						   pt_evt_config(decoder));
			break;

		case ppt_tma:
			/* Keep track of time. */
			errcode = pt_evt_apply_tma(&decoder->time,
						   &decoder->tcal,
						   &packet->payload.tma,
						   pt_evt_config(decoder));
			break;

		case ppt_mtc:
			/* Keep track of time. */
			errcode = pt_evt_apply_mtc(&decoder->time,
						   &decoder->tcal,
						   &packet->payload.mtc,
						   pt_evt_config(decoder));
			break;

		case ppt_cyc:
			/* Keep track of time. */
			errcode = pt_evt_apply_cyc(&decoder->time,
						   &decoder->tcal,
						   &packet->payload.cyc,
						   pt_evt_config(decoder));
			break;

		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
			/* We should not encounter those.
			 *
			 * We should not encounter a lot of packets but those
			 * are state-relevant; let's check them explicitly.
			 */
			return -pte_internal;

		case ppt_invalid:
		case ppt_unknown:
			/* We should not encounter those.
			 *
			 * We shouldn't have gotten here with those packets in
			 * our path.
			 */
			return -pte_internal;

		default:
			/* Skip other packets. */
			break;
		}

		if (errcode < 0)
			return errcode;
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_overflow;
	ev->ip_suppressed = 1;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

/* Handle erratum SKD010.
 *
 * Scan ahead for a packet at which to resume after an overflow.
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
 * recover by synchronizing at a later packet and a different IP.  We will
 * generate an overflow event with that IP and fetch the next packet.
 *
 * If we can't recover, pretend the erratum didn't apply so we run into the
 * error later.  Since this assumes that tracing is disabled, no harm should be
 * done, i.e. no bad trace should be generated.
 *
 * Returns zero if the erratum was handled and an overflow event was generated.
 * Returns a positive value if the overflow is not yet handled.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_evt_handle_skd010(struct pt_event_decoder *decoder)
{
	struct pt_packet_decoder pacdec;
	struct pt_time_cal tcal;
	struct pt_time time;
	struct {
		uint32_t found:1;
		uint32_t intx:1;
		uint32_t abrt:1;
	} mode_tsx;
	int errcode;

	if (!decoder)
		return -pte_internal;

	pacdec = decoder->pacdec;

	/* Keep track of time as we skip packets. */
	time = decoder->time;
	tcal = decoder->tcal;

	/* Keep track of a potential recovery point at MODE.TSX. */
	memset(&mode_tsx, 0, sizeof(mode_tsx));

	for (;;) {
		struct pt_packet packet;
		struct pt_event *ev;

		errcode = pt_pkt_next(&pacdec, &packet, sizeof(packet));
		if (errcode < 0) {
			/* Let's assume the trace is correct if we run out
			 * of packets.
			 */
			if (errcode == -pte_eos)
				errcode = 1;

			return errcode;
		}

		switch (packet.type) {
		case ppt_tip_pge:
			/* Everything is fine.  There is nothing to do. */
			return 1;

		case ppt_tip_pgd:
			/* This is a clear indication that the erratum
			 * applies.
			 *
			 * We synchronize after the disable.
			 */
			errcode = pt_evt_recover_ovf_disabled(decoder, &pacdec,
							      &packet, &time,
							      &tcal);
			if (errcode < 0)
				return errcode;

			return pt_evt_fetch_packet(decoder);

		case ppt_tnt_8:
		case ppt_tnt_64:
			/* This is a clear indication that the erratum
			 * apllies.
			 *
			 * Yet, we can't recover from it as we wouldn't know how
			 * many TNT bits will have been used when we eventually
			 * find an IP packet at which to resume tracing.
			 */
			return 1;

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
				 * the TIP IP but have to skip packets up to
				 * and including the TIP.
				 *
				 * We'd need to synthesize the MODE.EXEC event
				 * after the overflow event when recovering at
				 * the TIP.  We lack the infrastructure for
				 * this - it's getting too complicated.
				 *
				 * Instead, we ignore the execution mode
				 * change; we already don't know how many more
				 * such changes were lost in the overflow.
				 */
				break;

			case pt_mol_tsx: {
				struct pt_packet_mode_tsx *tsx;

				/* A MODE.TSX packet may be standalone or bind
				 * to FUP.
				 *
				 * If this is the second MODE.TSX, we're sure
				 * that tracing is disabled and everything is
				 * fine.
				 */
				if (mode_tsx.found)
					return 1;

				/* If we find the FUP this packet binds to, we
				 * may recover at the FUP IP and restart
				 * processing packets from here.  Remember the
				 * current state.
				 */
				tsx = &packet.payload.mode.bits.tsx;

				mode_tsx.found = 1;
				mode_tsx.intx = tsx->intx;
				mode_tsx.abrt = tsx->abrt;
			}
				break;
			}

			break;

		case ppt_fup:
			/* This is a pretty good indication that tracing
			 * is indeed enabled and the erratum applies.
			 *
			 * We overwrite the current packet with this FUP packet
			 * so on the next iteration we will resume from there.
			 */
			decoder->packet = packet;

			/* If we got a MODE.TSX packet before, we enqueue the
			 * tsx event.  We will process it after the overflow in
			 * the next iteration.
			 */
			if (mode_tsx.found) {
				ev = pt_evq_enqueue(&decoder->evq, evb_fup);
				if (!ev)
					return -pte_nomem;

				ev->type = ptev_tsx;
				ev->variant.tsx.speculative = mode_tsx.intx;
				ev->variant.tsx.aborted = mode_tsx.abrt;
			}

			return pt_evt_recover_ovf_at_ip(decoder, &pacdec,
							&packet,
							&packet.payload.ip,
							&time, &tcal);

		case ppt_tip:
			/* We syhchronize at the TIP IP and continue decoding
			 * packets after the TIP packet.
			 */
			errcode = pt_evt_recover_ovf_at_ip(decoder, &pacdec,
							   &packet,
							   &packet.payload.ip,
							   &time, &tcal);
			if (errcode < 0)
				return errcode;

			return pt_evt_fetch_packet(decoder);

		case ppt_psb: {
			struct pt_packet fup;

			/* We reached a synchronization point.  Tracing is
			 * enabled if and only if the PSB+ contains a FUP.
			 */
			errcode = pt_evt_find_header_fup(&fup, &pacdec);
			if (errcode < 0) {
				/* If we ran out of packets, we can't tell.
				 * Let's assume the trace is correct.
				 */
				if (errcode == -pte_eos)
					errcode = 1;

				return errcode;
			}

			/* If there is no FUP, tracing is disabled and
			 * everything is fine.
			 */
			if (!errcode)
				return 1;

			/* We must have a FUP. */
			if (fup.type != ppt_fup)
				return -pte_internal;

			return pt_evt_recover_ovf_at_ip(decoder, &pacdec,
							&packet,
							&fup.payload.ip,
							&time, &tcal);
		}

		case ppt_psbend:
			/* We shouldn't see this. */
			return -pte_bad_context;

		case ppt_ovf:
		case ppt_stop:
			/* It doesn't matter if it had been enabled or disabled
			 * before.  We may resume normally.
			 */
			return 1;

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

			return 1;

		case ppt_mwait:
			/* To skip this packet, we'd need to take care of the
			 * FUP it binds to.  This is getting complicated.
			 */
			return 1;

		case ppt_ptw:
			/* We may skip a stand-alone PTW. */
			if (!packet.payload.ptw.ip)
				break;

			/* To skip this packet, we'd need to take care of the
			 * FUP it binds to.  This is getting complicated.
			 */
			return 1;

		case ppt_tsc:
			/* Keep track of time. */
			errcode = pt_evt_apply_tsc(&time, &tcal,
						   &packet.payload.tsc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cbr:
			/* Keep track of time. */
			errcode = pt_evt_apply_cbr(&time, &tcal,
						   &packet.payload.cbr,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_tma:
			/* Keep track of time. */
			errcode = pt_evt_apply_tma(&time, &tcal,
						   &packet.payload.tma,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_mtc:
			/* Keep track of time. */
			errcode = pt_evt_apply_mtc(&time, &tcal,
						   &packet.payload.mtc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cyc:
			/* Keep track of time. */
			errcode = pt_evt_apply_cyc(&time, &tcal,
						   &packet.payload.cyc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_unknown:
		case ppt_invalid:
			/* We can't skip this packet. */
			return 1;
		}
	}
}

/* Handle erratum APL11.
 *
 * We search for a TIP.PGD and, if we find one, resume from after that packet
 * with tracing disabled.  On our way to the resume location we process packets
 * to update our state.
 *
 * If we don't find a TIP.PGD but instead some other packet that indicates that
 * tracing is disabled, indicate that the erratum does not apply.
 *
 * Any event will be dropped.
 *
 * Returns zero if the erratum was handled and an overflow event was generated.
 * Returns a positive value if the overflow is not yet handled.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_evt_handle_apl11(struct pt_event_decoder *decoder)
{
	struct pt_packet_decoder pacdec;
	struct pt_time_cal tcal;
	struct pt_time time;

	if (!decoder)
		return -pte_internal;

	pacdec = decoder->pacdec;
	time = decoder->time;
	tcal = decoder->tcal;
	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(&pacdec, &packet, sizeof(packet));
		if (errcode < 0)
			return errcode;

		switch (packet.type) {
		case ppt_tip_pgd:
			/* We found a TIP.PGD.  The erratum applies.
			 *
			 * Resume from here with tracing disabled.
			 */
			errcode = pt_evt_recover_ovf_disabled(decoder, &pacdec,
							      &packet, &time,
							      &tcal);

			return pt_evt_fetch_packet(decoder);

		case ppt_fup:
		case ppt_psb:
		case ppt_tip_pge:
		case ppt_stop:
		case ppt_ovf:
		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_exstop:
		case ppt_mwait:
		case ppt_pwre:
		case ppt_pwrx:
		case ppt_ptw:
			/* The erratum does not apply. */
			return 1;

		case ppt_psbend:
		case ppt_tip:
		case ppt_tnt_8:
		case ppt_tnt_64:
			/* Leave it to normal decode to diagnose those. */
			return 1;

		case ppt_tsc:
			/* Keep track of time. */
			errcode = pt_evt_apply_tsc(&time, &tcal,
						   &packet.payload.tsc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cbr:
			/* Keep track of time. */
			errcode = pt_evt_apply_cbr(&time, &tcal,
						   &packet.payload.cbr,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_tma:
			/* Keep track of time. */
			errcode = pt_evt_apply_tma(&time, &tcal,
						   &packet.payload.tma,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_mtc:
			/* Keep track of time. */
			errcode = pt_evt_apply_mtc(&time, &tcal,
						   &packet.payload.mtc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_cyc:
			/* Keep track of time. */
			errcode = pt_evt_apply_cyc(&time, &tcal,
						   &packet.payload.cyc,
						   &pacdec.config);
			if (errcode < 0)
				return errcode;

			break;

		case ppt_pad:
		case ppt_mnt:
			/* Skip those packets. */
			break;

		case ppt_unknown:
		case ppt_invalid:
			/* We can't skip this packet. */
			return 1;
		}
	}
}


/* Handle erratum APL12.
 *
 * This function is called when a FUP is found after an OVF.  The @offset
 * argument gives the relative offset from @decoder's current position to after
 * the FUP.
 *
 * A FUP after OVF normally indicates that the overflow resolved while tracing
 * is enabled.  Due to erratum APL12, however, the overflow may have resolved
 * while tracing is disabled and still generate a FUP.
 *
 * We scan ahead for an indication whether tracing is actually disabled.  If we
 * find one, the erratum applies and we proceed from after the FUP with tracing
 * disabled.
 *
 * This will drop any CBR events.  We will update @decoder's timing state on
 * CBR but drop the event.
 *
 * Returns zero if the erratum was handled and an overflow event was generated.
 * Returns a positive value if the overflow is not yet handled.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_evt_handle_apl12(struct pt_event_decoder *decoder,
			       uint64_t offset)
{
	struct pt_packet_decoder pacdec;

	if (!decoder)
		return -pte_internal;

	pacdec = decoder->pacdec;
	pacdec.pos += offset;
	if (pt_pkt_end(&pacdec) < pt_pkt_pos(&pacdec))
		return -pte_internal;

	for (;;) {
		struct pt_packet packet;
		int errcode;

		errcode = pt_pkt_next(&pacdec, &packet, sizeof(packet));
		if (errcode < 0) {
			/* Running out of packets is not an error. */
			if (errcode == -pte_eos)
				errcode = 1;

			return errcode;
		}

		switch (packet.type) {
		case ppt_tnt_8:
		case ppt_tnt_64:
		case ppt_tip:
		case ppt_tip_pgd:
			/* Those packets are only generated when tracing is
			 * enabled.  We're done.
			 */
			return 1;

		case ppt_psb:
			/* We reached a synchronization point.  Tracing is
			 * enabled if and only if the PSB+ contains a FUP.
			 */
			errcode = pt_evt_find_header_fup(&packet, &pacdec);
			if (errcode != 0) {
				/* If we ran out of packets, we can't tell. */
				if (errcode == -pte_eos)
					errcode = 1;

				return errcode;
			}

			return pt_evt_recover_ovf_at_offset(decoder, offset);

		case ppt_stop:
			/* Tracing is disabled before a stop. */

			return pt_evt_recover_ovf_at_offset(decoder, offset);

		case ppt_tip_pge:
			/* Tracing must have been disabled. */

			return pt_evt_recover_ovf_at_offset(decoder, offset);

		case ppt_psbend:
			/* Leave it to normal decode to diagnose. */
			return 1;

		case ppt_ovf:
			/* It doesn't matter - we run into the next overflow. */
			return 1;

		case ppt_pad:
		case ppt_fup:
		case ppt_tsc:
		case ppt_cbr:
		case ppt_tma:
		case ppt_mtc:
		case ppt_cyc:
		case ppt_exstop:
		case ppt_mwait:
		case ppt_pwre:
		case ppt_pwrx:
		case ppt_ptw:
		case ppt_mnt:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_mode:
			/* Skip those packets. */
			break;

		case ppt_unknown:
		case ppt_invalid:
			/* We can't skip those packets. */
			return 1;
		}
	}
}

static int pt_evt_decode_ovf(struct pt_event_decoder *decoder)
{
	const struct pt_config *config;
	struct pt_time_cal tcal;
	struct pt_time time;
	struct pt_event *ev;
	int errcode, offset;

	if (!decoder)
		return -pte_internal;

	/* An OVF ends a PSB just like PSBEND.
	 *
	 * Publish any pending PSB+ events before we start handling the actual
	 * overflow event.
	 */
	errcode = pt_evt_decode_psbend(decoder);
	if (errcode <= 0)
		return errcode;

	config = pt_evt_config(decoder);
	if (!config)
		return -pte_internal;

	/* Reset the decoder state but preserve timing. */
	time = decoder->time;
	tcal = decoder->tcal;

	errcode = pt_evt_reset(decoder);
	if (errcode < 0)
		return errcode;

	decoder->time = time;
	if (decoder->flags.variant.event.keep_tcal_on_ovf) {
		errcode = pt_tcal_update_ovf(&tcal, config);
		if (errcode < 0)
			return errcode;

		decoder->tcal = tcal;
	}

	/* OVF binds to either FUP or TIP.PGE.
	 *
	 * If the overflow resolves while PacketEn=1 it binds to FUP.  We can
	 * see timing packets between OVF and FUP but that's it.
	 *
	 * If the overflow resolves while PacketEn=0 it binds to TIP.PGE.  We
	 * can see packets between OVF and TIP.PGE that do not depend on
	 * PacketEn.
	 *
	 * We don't need to decode everything until TIP.PGE, however.  As soon
	 * as we see a non-timing non-FUP packet, we know that tracing has been
	 * disabled before the overflow resolves.  We generate a standalone
	 * overflow event and continue decoding normally.
	 *
	 * We search for a FUP and, if we find one, return its offset from the
	 * current decoder position.  An offset of zero means that we did not
	 * find a FUP and negative values indicate errors.
	 */
	offset = pt_evt_find_ovf_fup(&decoder->pacdec);
	if (offset <= 0) {
		/* Check for erratum SKD010.
		 *
		 * The FUP may have been dropped.  If we can figure out that
		 * tracing is enabled and hence the FUP is missing, we resume
		 * at a later packet and a different IP.
		 */
		if (config->errata.skd010) {
			errcode = pt_evt_handle_skd010(decoder);
			if (errcode <= 0)
				return errcode;
		}

		/* Check for erratum APL11.
		 *
		 * We may have gotten an extra TIP.PGD, which should be
		 * diagnosed by our search for a subsequent FUP.
		 */
		if (config->errata.apl11 &&
		    (offset == -pte_bad_context)) {
			errcode = pt_evt_handle_apl11(decoder);
			if (errcode <= 0)
				return errcode;
		}

		/* Report the original error from searching for the FUP packet
		 * if we were not able to fix the trace.
		 *
		 * We treat an overflow at the end of the trace as standalone.
		 */
		if ((offset < 0) && (offset != -pte_eos))
			return offset;

		decoder->event = ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;

		ev->type = ptev_overflow;
		ev->ip_suppressed = 1;

		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			return errcode;

		return pt_evt_fetch_packet(decoder);
	}

	/* Check for erratum APL12.
	 *
	 * We may get an extra FUP even though the overflow resolved with
	 * tracing disabled.
	 */
	if (config->errata.apl12) {
		errcode = pt_evt_handle_apl12(decoder, (uint64_t) offset);
		if (errcode <= 0)
			return errcode;
	}

	ev = pt_evq_enqueue(&decoder->evq, evb_fup);
	if (!ev)
		return -pte_nomem;

	ev->type = ptev_overflow;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return 1;
}

static int pt_evt_decode_tip_event(struct pt_event_decoder *decoder)
{
	struct pt_event *ev, *async;
	int errcode;

	if (!decoder)
		return -pte_internal;

	decoder->bound = 1;

	async = pt_evq_find(&decoder->evq, evb_tip, ptev_async_branch);
	if (async) {
		ev = pt_evq_dequeue(&decoder->evq, evb_tip);
		if (!ev)
			return -pte_internal;

		/* Swap the asynchronous branch event with the first event. */
		if (ev != async) {
			struct pt_event tmp;

			tmp = *async;
			*async = *ev;
			*ev = tmp;
		}

		if (ev->type != ptev_async_branch)
			return -pte_internal;

		decoder->event = ev;

		errcode = pt_evt_event_ip(&ev->variant.async_branch.to, ev,
					  &decoder->ip);
		if (errcode < 0)
			return errcode;

		return pt_evt_event_time(ev, &decoder->time);
	}

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_tip;

	errcode = pt_evt_event_ip(&ev->variant.tip.ip, ev, &decoder->ip);
	if (errcode < 0)
		return errcode;

	return pt_evt_event_time(ev, &decoder->time);
}

static int pt_evt_decode_tip(struct pt_event_decoder *decoder,
			     const struct pt_packet_ip *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	if (!decoder->enabled)
		return -pte_bad_context;

	errcode = pt_last_ip_update_ip(&decoder->ip, packet,
				       pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	/* Send the async or sync branch event first.
	 *
	 * That's a bit more complicated for us but it will help our users as
	 * non-async branch events bind to the branch IP, not to the
	 * instruction IP.
	 */
	if (!decoder->bound)
		return pt_evt_decode_tip_event(decoder);

	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	if (!ev)
		return 1;

	decoder->event = ev;

	switch (ev->type) {
	case ptev_async_branch:
		return -pte_internal;

	case ptev_exec_mode:
		errcode = pt_evt_event_ip(&ev->variant.exec_mode.ip, ev,
					  &decoder->ip);
		break;

	case ptev_async_paging:
		errcode = pt_evt_event_ip(&ev->variant.async_paging.ip, ev,
					  &decoder->ip);
		break;

	case ptev_async_vmcs:
		errcode = pt_evt_event_ip(&ev->variant.async_vmcs.ip, ev,
					  &decoder->ip);
		break;

	default:
		errcode = -pte_bad_context;
		break;
	}

	if (errcode < 0)
		return errcode;

	return pt_evt_event_time(ev, &decoder->time);
}

static int pt_evt_decode_tip_pge(struct pt_event_decoder *decoder,
				 const struct pt_packet_ip *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	errcode = pt_last_ip_update_ip(&decoder->ip, packet,
				       pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	/* We send the enable event first. This is more convenient for our
	 * users and does not require them to either store or blindly apply
	 * other events that might be pending.
	 *
	 * We use the bound decoder flag to indicate this.
	 */
	if (!decoder->bound) {
		decoder->event = ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;

		ev->type = ptev_enabled;

		errcode = pt_evt_event_ip(&ev->variant.enabled.ip, ev,
					  &decoder->ip);
		if (errcode < 0)
			return errcode;

		decoder->enabled = 1;
		decoder->bound = 1;

		return pt_evt_event_time(ev, &decoder->time);
	}

	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	if (!ev)
		return 1;

	decoder->event = ev;

	switch (ev->type) {
	case ptev_exec_mode:
		errcode = pt_evt_event_ip(&ev->variant.exec_mode.ip, ev,
					  &decoder->ip);
		break;

	default:
		errcode = -pte_bad_context;
		break;
	}

	if (errcode < 0)
		return errcode;

	return pt_evt_event_time(ev, &decoder->time);
}

static int pt_evt_decode_tip_pgd(struct pt_event_decoder *decoder,
				 const struct pt_packet_ip *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	errcode = pt_last_ip_update_ip(&decoder->ip, packet,
				       pt_evt_config(decoder));
	if (errcode < 0)
		return errcode;

	ev = pt_evq_dequeue(&decoder->evq, evb_tip);
	if (!ev) {
		if (decoder->bound)
			return 1;

		decoder->event = ev = pt_evq_standalone(&decoder->evq);
		if (!ev)
			return -pte_internal;

		ev->type = ptev_disabled;

		errcode = pt_evt_event_ip(&ev->variant.disabled.ip, ev,
					  &decoder->ip);
		if (errcode < 0)
			return errcode;

		errcode = pt_evt_event_time(ev, &decoder->time);
		if (errcode < 0)
			return errcode;

		decoder->enabled = 0;

		return pt_evt_fetch_packet(decoder);
	}

	decoder->event = ev;

	switch (ev->type) {
	case ptev_async_branch: {
		uint64_t at;

		/* Turn the async branch into an async disable. */
		at = ev->variant.async_branch.from;

		ev->type = ptev_async_disabled;
		ev->variant.async_disabled.at = at;

		errcode = pt_evt_event_ip(&ev->variant.async_disabled.ip, ev,
					  &decoder->ip);

		decoder->enabled = 0;
		decoder->bound = 1;

		break;
	}

	case ptev_async_paging:
	case ptev_async_vmcs:
		/* The async paging and vmcs events are ordered after the async
		 * branch event that we turned into an async disable above.
		 */
		if (!decoder->bound)
			return -pte_internal;

		fallthrough;
	case ptev_exec_mode:
		/* The MODE.EXEC might come with a standalone TIP.PGD or with a
		 * FUP + TIP.PGD pair.  In both cases, we won't really reach
		 * the IP in the TIP.PGD's payload since tracing is disabled as
		 * part of the branch.  In the synchronous case, we won't get a
		 * TIP event that would allow us to reach the MODE.EXEC's event
		 * location.
		 *
		 * It is not quite clear what IP to give those events.
		 *
		 * If we give them the async disable's source IP, we'd make an
		 * error if the IP is updated when applying the async disable
		 * event.
		 *
		 * If we give them the async disable's destination IP, we'd make
		 * an error if the IP is not updated when applying the async
		 * disable event.  That's what our decoders do since tracing is
		 * likely to resume from there.
		 *
		 * In all cases, tracing will be disabled when those events are
		 * applied, so we may as well suppress the IP.
		 */
		ev->ip_suppressed = 1;
		break;

	default:
		errcode = -pte_bad_context;
		break;
	}

	if (errcode < 0)
		return errcode;

	return pt_evt_event_time(ev, &decoder->time);
}

static int pt_evt_decode_tnt(struct pt_event_decoder *decoder,
			     const struct pt_packet_tnt *packet)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !packet)
		return -pte_internal;

	if (!decoder->enabled)
		return -pte_bad_context;

	decoder->event = ev = pt_evq_standalone(&decoder->evq);
	if (!ev)
		return -pte_internal;

	ev->type = ptev_tnt;
	ev->variant.tnt.bits = packet->payload;
	ev->variant.tnt.size = packet->bit_size;

	errcode = pt_evt_event_time(ev, &decoder->time);
	if (errcode < 0)
		return errcode;

	return pt_evt_fetch_packet(decoder);
}

static int pt_evt_decode_unknown(struct pt_event_decoder *decoder,
				 const struct pt_packet_unknown *packet)
{
	(void) decoder;
	(void) packet;

	return 1;
}

static int pt_evt_decode_packet(struct pt_event_decoder *decoder)
{
	const struct pt_packet *packet;
	int errcode;

	if (!decoder)
		return -pte_internal;

	packet = &decoder->packet;
	switch (packet->type) {
	case ppt_tnt_8:
	case ppt_tnt_64:
		return pt_evt_decode_tnt(decoder, &packet->payload.tnt);

	case ppt_cyc:
		return pt_evt_decode_cyc(decoder, &packet->payload.cyc);

	case ppt_pad:
		return 1;

	case ppt_fup:
		return pt_evt_decode_fup(decoder, &packet->payload.ip);

	case ppt_tip:
		return pt_evt_decode_tip(decoder, &packet->payload.ip);

	case ppt_mtc:
		return pt_evt_decode_mtc(decoder, &packet->payload.mtc);

	case ppt_tsc:
		return pt_evt_decode_tsc(decoder, &packet->payload.tsc);

	case ppt_cbr:
		return pt_evt_decode_cbr(decoder, &packet->payload.cbr);

	case ppt_tma:
		return pt_evt_decode_tma(decoder, &packet->payload.tma);

	case ppt_mode:
		return pt_evt_decode_mode(decoder, &packet->payload.mode);

	case ppt_pip:
		return pt_evt_decode_pip(decoder, &packet->payload.pip);

	case ppt_ptw:
		return pt_evt_decode_ptw(decoder, &packet->payload.ptw);

	case ppt_psb:
		errcode = pt_evt_decode_psb(decoder);
		if (errcode <= 0)
			return errcode;

		return pt_evt_decode_packet(decoder);

	case ppt_psbend:
		return pt_evt_decode_psbend(decoder);

	case ppt_tip_pge:
		return pt_evt_decode_tip_pge(decoder, &packet->payload.ip);

	case ppt_tip_pgd:
		return pt_evt_decode_tip_pgd(decoder, &packet->payload.ip);

	case ppt_exstop:
		return pt_evt_decode_exstop(decoder, &packet->payload.exstop);

	case ppt_pwre:
		return pt_evt_decode_pwre(decoder, &packet->payload.pwre);

	case ppt_pwrx:
		return pt_evt_decode_pwrx(decoder, &packet->payload.pwrx);

	case ppt_mwait:
		return pt_evt_decode_mwait(decoder, &packet->payload.mwait);

	case ppt_vmcs:
		return pt_evt_decode_vmcs(decoder, &packet->payload.vmcs);

	case ppt_ovf:
		return pt_evt_decode_ovf(decoder);

	case ppt_stop:
		return pt_evt_decode_stop(decoder);

	case ppt_mnt:
		return pt_evt_decode_mnt(decoder, &packet->payload.mnt);

	case ppt_invalid:
		if (decoder->status < 0)
			return decoder->status;

		return 1;

	case ppt_unknown:
		return pt_evt_decode_unknown(decoder,
					     &packet->payload.unknown);
	}

	return -pte_bad_opc;
}

/* Fetch the next event.
 *
 * Calls packet decode functions until one signals that it reported an event by
 * returning zero.
 *
 * Packet decode functions return:
 *
 *    zero.......an event was created
 *    negative...an error occurred during packet processing
 *    positive...further packets are needed
 *
 * When indicating that an event was created, packet decode functions must
 * fetch the next packet if they are done processing the current packet,
 * e.g. by returning via:
 *
 *     return pt_evt_fetch_packet(decoder);
 *
 * If they are not done processing the current packet, e.g. when more events
 * have been enqueued for this packet, they must return via:
 *
 *     return 0;
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_evt_fetch_event(struct pt_event_decoder *decoder)
{
	int errcode;

	if (!decoder)
		return -pte_internal;

	for (;;) {
		errcode = pt_evt_decode_packet(decoder);
		if (errcode <= 0)
			break;

		if (decoder->event) {
			errcode = -pte_internal;
			break;
		}

		/* The packet decoder asked for a new packet without delivering
		 * an event.  That new packet isn't bound.
		 *
		 * All flows involving bound packets must take this path since
		 * returning with zero, e.g. via pt_evt_fetch_packet(), without
		 * an event will be diagnosed by our caller.
		 */
		decoder->bound = 0;

		errcode = pt_evt_fetch_packet(decoder);
		if (errcode < 0)
			break;
	}

	return errcode;
}

static inline int pt_evt_to_user(struct pt_event *uev, size_t size,
				 const struct pt_event *ev)
{
	if (!uev || !ev)
		return -pte_internal;

	/* Zero out any unknown bytes. */
	if (sizeof(*ev) < size) {
		memset(uev + sizeof(*ev), 0, size - sizeof(*ev));

		size = sizeof(*ev);
	}

	memcpy(uev, ev, size);

	return 0;
}

int pt_evt_next(struct pt_event_decoder *decoder, struct pt_event *uev,
		size_t size)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !uev)
		return -pte_invalid;

	errcode = pt_evt_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	ev = decoder->event;
	decoder->event = NULL;

	return pt_evt_to_user(uev, size, ev);
}
