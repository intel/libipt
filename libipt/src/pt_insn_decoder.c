/*
 * Copyright (c) 2013-2017, Intel Corporation
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

#include "pt_insn_decoder.h"
#include "pt_insn.h"
#include "pt_config.h"
#include "pt_asid.h"

#include "intel-pt.h"

#include <string.h>
#include <stdlib.h>


static int process_events_peek(struct pt_insn_decoder *, struct pt_insn *,
			       const struct pt_insn_ext *);


static void pt_insn_reset(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return;

	decoder->mode = ptem_unknown;
	decoder->ip = 0ull;
	decoder->last_disable_ip = 0ull;
	decoder->status = 0;
	decoder->enabled = 0;
	decoder->process_event = 0;
	decoder->speculative = 0;
	decoder->event_may_change_ip = 1;

	pt_retstack_init(&decoder->retstack);
	pt_asid_init(&decoder->asid);
}

static int pt_insn_status(const struct pt_insn_decoder *decoder, int flags)
{
	int status;

	if (!decoder)
		return -pte_internal;

	status = decoder->status;

	/* Indicate whether tracing is disabled or enabled.
	 *
	 * This duplicates the indication in struct pt_insn and covers the case
	 * where we indicate the status after synchronizing.
	 */
	if (!decoder->enabled)
		flags |= pts_ip_suppressed;

	/* Forward end-of-trace indications.
	 *
	 * Postpone it as long as we're still processing events, though.
	 */
	if ((status & pts_eos) && !decoder->process_event)
		flags |= pts_eos;

	return flags;
}

/* Initialize the query decoder flags based on our flags. */

static int pt_insn_init_qry_flags(struct pt_conf_flags *qflags,
				  const struct pt_conf_flags *flags)
{
	if (!qflags || !flags)
		return -pte_internal;

	memset(qflags, 0, sizeof(*qflags));

	return 0;
}

int pt_insn_decoder_init(struct pt_insn_decoder *decoder,
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

	/* Set the flags we need for the query decoder we use. */
	errcode = pt_insn_init_qry_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	errcode = pt_qry_decoder_init(&decoder->query, &config);
	if (errcode < 0)
		return errcode;

	pt_image_init(&decoder->default_image, NULL);
	decoder->image = &decoder->default_image;

	pt_insn_reset(decoder);

	return 0;
}

void pt_insn_decoder_fini(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return;

	pt_image_fini(&decoder->default_image);
	pt_qry_decoder_fini(&decoder->query);
}

struct pt_insn_decoder *pt_insn_alloc_decoder(const struct pt_config *config)
{
	struct pt_insn_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_insn_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_insn_free_decoder(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return;

	pt_insn_decoder_fini(decoder);
	free(decoder);
}

static int pt_insn_start(struct pt_insn_decoder *decoder, int status)
{
	if (!decoder)
		return -pte_internal;

	if (status < 0)
		return status;

	decoder->status = status;

	if (!(status & pts_ip_suppressed))
		decoder->enabled = 1;

	/* Process any initial events.
	 *
	 * Some events are processed after proceeding to the next IP in order to
	 * indicate things like tracing disable or trace stop in the preceding
	 * instruction.  Those events will be processed without such an
	 * indication before decoding the current instruction.
	 *
	 * We do this already here so we can indicate user-events that precede
	 * the first instruction.
	 */
	return process_events_peek(decoder, NULL, NULL);
}

int pt_insn_sync_forward(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_qry_sync_forward(&decoder->query, &decoder->ip);

	return pt_insn_start(decoder, status);
}

int pt_insn_sync_backward(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_qry_sync_backward(&decoder->query, &decoder->ip);

	return pt_insn_start(decoder, status);
}

int pt_insn_sync_set(struct pt_insn_decoder *decoder, uint64_t offset)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_qry_sync_set(&decoder->query, &decoder->ip, offset);

	return pt_insn_start(decoder, status);
}

int pt_insn_get_offset(struct pt_insn_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_get_offset(&decoder->query, offset);
}

int pt_insn_get_sync_offset(struct pt_insn_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_get_sync_offset(&decoder->query, offset);
}

struct pt_image *pt_insn_get_image(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return decoder->image;
}

int pt_insn_set_image(struct pt_insn_decoder *decoder,
		      struct pt_image *image)
{
	if (!decoder)
		return -pte_invalid;

	if (!image)
		image = &decoder->default_image;

	decoder->image = image;
	return 0;
}

const struct pt_config *
pt_insn_get_config(const struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_qry_get_config(&decoder->query);
}

int pt_insn_time(struct pt_insn_decoder *decoder, uint64_t *time,
		 uint32_t *lost_mtc, uint32_t *lost_cyc)
{
	if (!decoder || !time)
		return -pte_invalid;

	return pt_qry_time(&decoder->query, time, lost_mtc, lost_cyc);
}

int pt_insn_core_bus_ratio(struct pt_insn_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	return pt_qry_core_bus_ratio(&decoder->query, cbr);
}

int pt_insn_asid(const struct pt_insn_decoder *decoder, struct pt_asid *asid,
		 size_t size)
{
	if (!decoder || !asid)
		return -pte_invalid;

	return pt_asid_to_user(asid, &decoder->asid, size);
}

static inline int event_pending(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	if (decoder->process_event)
		return 1;

	status = decoder->status;
	if (!(status & pts_event_pending))
		return 0;

	status = pt_qry_event(&decoder->query, &decoder->event,
			      sizeof(decoder->event));
	if (status < 0)
		return status;

	decoder->process_event = 1;
	decoder->status = status;
	return 1;
}

static int pt_insn_process_enabled(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must have an IP in order to start decoding. */
	if (ev->ip_suppressed)
		return -pte_noip;

	/* We must currently be disabled. */
	if (decoder->enabled)
		return -pte_bad_context;

	/* We're processing the event outside of pt_insn_next() - we must be
	 * able to change the IP.
	 */
	if (!decoder->event_may_change_ip)
		return -pte_internal;

	decoder->ip = ev->variant.enabled.ip;
	decoder->enabled = 1;

	return 0;
}

static int pt_insn_process_disabled(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	decoder->enabled = 0;

	return 0;
}

static int pt_insn_process_async_branch(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* Tracing must be enabled in order to make sense of the event. */
	if (!decoder->enabled)
		return -pte_bad_context;

	decoder->ip = ev->variant.async_branch.to;

	return 0;
}

static int pt_insn_process_paging(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->asid.cr3 = decoder->event.variant.paging.cr3;

	return 0;
}

static int pt_insn_process_overflow(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* If the IP is suppressed, the overflow resolved while tracing was
	 * disabled.  Otherwise it resolved while tracing was enabled.
	 */
	if (ev->ip_suppressed) {
		/* Tracing is disabled.
		 *
		 * It doesn't make sense to preserve the previous IP.  This will
		 * just be misleading.  Even if tracing had been disabled
		 * before, as well, we might have missed the re-enable in the
		 * overflow.
		 */
		decoder->enabled = 0;
		decoder->ip = 0ull;
	} else {
		if (!decoder->event_may_change_ip)
			return -pte_internal;

		/* Tracing is enabled and we're at the IP at which the overflow
		 * resolved.
		 */
		decoder->ip = ev->variant.overflow.ip;
		decoder->enabled = 1;
	}

	/* We don't know the TSX state.  Let's assume we execute normally.
	 *
	 * We also don't know the execution mode.  Let's keep what we have
	 * in case we don't get an update before we have to decode the next
	 * instruction.
	 */
	decoder->speculative = 0;

	return 0;
}

static int pt_insn_process_exec_mode(struct pt_insn_decoder *decoder)
{
	enum pt_exec_mode mode;
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	mode = ev->variant.exec_mode.mode;

	/* Use status update events to diagnose inconsistencies. */
	if (ev->status_update && decoder->enabled &&
	    decoder->mode != ptem_unknown && decoder->mode != mode)
		return -pte_bad_status_update;

	decoder->mode = mode;

	return 0;
}

static int pt_insn_process_tsx(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->speculative = decoder->event.variant.tsx.speculative;

	return 0;
}

static int pt_insn_process_stop(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* Tracing is always disabled before it is stopped. */
	if (decoder->enabled)
		return -pte_bad_context;

	return 0;
}

static int pt_insn_process_vmcs(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->asid.vmcs = decoder->event.variant.vmcs.base;

	return 0;
}

static int check_erratum_skd022(struct pt_insn_decoder *decoder)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int errcode;

	if (!decoder)
		return -pte_internal;

	insn.mode = decoder->mode;
	insn.ip = decoder->ip;

	errcode = pt_insn_decode(&insn, &iext, decoder->image, &decoder->asid);
	if (errcode < 0)
		return 0;

	switch (iext.iclass) {
	default:
		return 0;

	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		return 1;
	}
}

static inline int handle_erratum_skd022(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;
	uint64_t ip;
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = check_erratum_skd022(decoder);
	if (errcode <= 0)
		return errcode;

	/* We turn the async disable into a sync disable.  It will be processed
	 * after decoding the instruction.
	 */
	ev = &decoder->event;

	ip = ev->variant.async_disabled.ip;

	ev->type = ptev_disabled;
	ev->variant.disabled.ip = ip;

	return 1;
}

static int process_one_event_before(struct pt_insn_decoder *decoder,
				    struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder || !insn)
		return -pte_internal;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_enabled:
		/* We should have processed the event before. */
		return -pte_bad_query;

	case ptev_async_branch:
		/* We should have processed the event before. */
		if (decoder->ip == ev->variant.async_branch.from)
			return -pte_bad_query;

		return 0;

	case ptev_async_disabled:
		/* We should have processed the event before. */
		if (ev->variant.async_disabled.at == decoder->ip)
			return -pte_bad_query;

		return 0;

	case ptev_async_paging:
		/* We should have processed the event before. */
		if (ev->ip_suppressed ||
		    ev->variant.async_paging.ip == decoder->ip)
			return -pte_bad_query;

		return 0;

	case ptev_async_vmcs:
		/* We should have processed the event before. */
		if (ev->ip_suppressed ||
		    ev->variant.async_vmcs.ip == decoder->ip)
			return -pte_bad_query;

		return 0;

	case ptev_disabled:
		return 0;

	case ptev_paging:
		/* We should have processed the event before. */
		if (!decoder->enabled)
			return -pte_bad_query;

		return 0;

	case ptev_vmcs:
		/* We should have processed the event before. */
		if (!decoder->enabled)
			return -pte_bad_query;

		return 0;

	case ptev_overflow:
		/* We should have processed the event before. */
		return -pte_bad_query;

	case ptev_exec_mode:
		/* We should have processed the event before. */
		if (ev->ip_suppressed ||
		    ev->variant.exec_mode.ip == decoder->ip)
			return -pte_bad_query;

		return 0;

	case ptev_tsx:
		/* We should have processed the event before. */
		if (ev->ip_suppressed ||
		    ev->variant.tsx.ip == decoder->ip)
			return -pte_bad_query;

		return 0;

	case ptev_stop:
		/* We should have processed the event before. */
		return -pte_bad_query;

	case ptev_exstop:
		/* We should have indicated this event at the current location
		 * after the last instruction or the last decoder
		 * synchronization.
		 */
		if (ev->ip_suppressed ||
		    decoder->ip == ev->variant.exstop.ip)
			return -pte_bad_query;

		return 0;

	case ptev_mwait:
		/* We should have indicated this event at the current location
		 * after the last instruction or the last decoder
		 * synchronization.
		 */
		if (ev->ip_suppressed ||
		    decoder->ip == ev->variant.mwait.ip)
			return -pte_bad_query;

		return 0;

	case ptev_pwre:
	case ptev_pwrx:
		/* We should have indicated this event after the last
		 * instruction or the last decoder synchronization.
		 */
		return -pte_bad_query;

	case ptev_ptwrite:
		return 0;
	}

	/* Diagnose an unknown event. */
	return -pte_internal;
}

static int process_events_before(struct pt_insn_decoder *decoder,
				 struct pt_insn *insn)
{
	if (!decoder || !insn)
		return -pte_internal;

	for (;;) {
		int pending, processed;

		pending = event_pending(decoder);
		if (pending < 0)
			return pending;

		if (!pending)
			break;

		processed = process_one_event_before(decoder, insn);
		if (processed < 0)
			return processed;

		if (!processed)
			break;

		decoder->process_event = 0;
	}

	return 0;
}

static int pt_insn_proceed(struct pt_insn_decoder *decoder,
			   const struct pt_insn *insn,
			   const struct pt_insn_ext *iext)
{
	if (!decoder || !insn || !iext)
		return -pte_internal;

	/* Branch displacements apply to the next instruction. */
	decoder->ip += insn->size;

	/* We handle non-branches, non-taken conditional branches, and
	 * compressed returns directly in the switch and do some pre-work for
	 * calls.
	 *
	 * All kinds of branches are handled below the switch.
	 */
	switch (insn->iclass) {
	case ptic_ptwrite:
	case ptic_other:
		return 0;

	case ptic_cond_jump: {
		int status, taken;

		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status < 0)
			return status;

		decoder->status = status;
		if (!taken)
			return 0;

		break;
	}

	case ptic_call:
		/* Log the call for return compression.
		 *
		 * Unless this is a call to the next instruction as is used
		 * for position independent code.
		 */
		if (iext->variant.branch.displacement ||
		    !iext->variant.branch.is_direct)
			pt_retstack_push(&decoder->retstack, decoder->ip);

		break;

	case ptic_return: {
		int taken, status;

		/* Check for a compressed return. */
		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status >= 0) {
			decoder->status = status;

			/* A compressed return is indicated by a taken
			 * conditional branch.
			 */
			if (!taken)
				return -pte_bad_retcomp;

			return pt_retstack_pop(&decoder->retstack,
					       &decoder->ip);
		}

		break;
	}

	case ptic_jump:
	case ptic_far_call:
	case ptic_far_return:
	case ptic_far_jump:
		break;

	case ptic_error:
		return -pte_bad_insn;
	}

	/* Process a direct or indirect branch.
	 *
	 * This combines calls, uncompressed returns, taken conditional jumps,
	 * and all flavors of far transfers.
	 */
	if (iext->variant.branch.is_direct)
		decoder->ip += iext->variant.branch.displacement;
	else {
		int status;

		status = pt_qry_indirect_branch(&decoder->query,
						&decoder->ip);

		if (status < 0)
			return status;

		decoder->status = status;

		/* We do need an IP to proceed. */
		if (status & pts_ip_suppressed)
			return -pte_noip;
	}

	return 0;
}

static int pt_insn_at_disabled_event(const struct pt_event *ev,
				     const struct pt_insn *insn,
				     const struct pt_insn_ext *iext)
{
	if (!ev || !insn || !iext)
		return -pte_internal;

	if (ev->ip_suppressed) {
		if (pt_insn_is_far_branch(insn, iext) ||
		    pt_insn_changes_cpl(insn, iext) ||
		    pt_insn_changes_cr3(insn, iext))
			return 1;

	} else {
		switch (insn->iclass) {
		case ptic_ptwrite:
		case ptic_other:
			break;

		case ptic_call:
		case ptic_jump:
			/* If we got an IP with the disabled event, we may
			 * ignore direct branches that go to a different IP.
			 */
			if (iext->variant.branch.is_direct) {
				uint64_t ip;

				ip = insn->ip;
				ip += insn->size;
				ip += iext->variant.branch.displacement;

				if (ip != ev->variant.disabled.ip)
					break;
			}

			/* Fall through. */
		case ptic_return:
		case ptic_far_call:
		case ptic_far_return:
		case ptic_far_jump:
		case ptic_cond_jump:
			return 1;

		case ptic_error:
			return -pte_bad_insn;
		}
	}

	return 0;
}

static int process_events_after(struct pt_insn_decoder *decoder,
				struct pt_insn *insn,
				const struct pt_insn_ext *iext)
{
	if (!decoder)
		return -pte_internal;

	for (;;) {
		struct pt_event *ev;
		int status;

		status = event_pending(decoder);
		if (status <= 0) {
			if (status < 0)
				return status;

			break;
		}

		ev = &decoder->event;
		switch (ev->type) {
		case ptev_enabled:
		case ptev_overflow:
		case ptev_async_paging:
		case ptev_async_vmcs:
		case ptev_async_disabled:
		case ptev_async_branch:
		case ptev_exec_mode:
		case ptev_tsx:
		case ptev_stop:
		case ptev_exstop:
		case ptev_mwait:
		case ptev_pwre:
		case ptev_pwrx:
			break;

		case ptev_disabled:
			status = pt_insn_at_disabled_event(ev, insn, iext);
			if (status <= 0) {
				if (status < 0)
					return status;

				break;
			}

			/* We're at a synchronous disable event location.
			 *
			 * Let's determine the IP at which we expect tracing to
			 * resume.
			 */
			status = pt_insn_next_ip(&decoder->last_disable_ip,
						 insn, iext);
			if (status < 0) {
				/* We don't know the IP on error. */
				decoder->last_disable_ip = 0ull;

				/* For indirect calls, assume that we return to
				 * the next instruction.
				 *
				 * We only check the instruction class, not the
				 * is_direct property, since direct calls would
				 * have been handled by pt_insn_nex_ip() or
				 * would have provoked a different error.
				 */
				if (status != -pte_bad_query)
					return status;

				switch (insn->iclass) {
				case ptic_call:
				case ptic_far_call:
					decoder->last_disable_ip =
						insn->ip + insn->size;
					break;

				default:
					break;
				}
			}

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_paging:
			if (!pt_insn_binds_to_pip(insn, iext))
				break;

			status = pt_insn_proceed(decoder, insn, iext);
			if (status < 0)
				return status;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_vmcs:
			if (!pt_insn_binds_to_vmcs(insn, iext))
				break;

			status = pt_insn_proceed(decoder, insn, iext);
			if (status < 0)
				return status;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_ptwrite:
			if (ev->ip_suppressed) {
				if (insn->iclass != ptic_ptwrite)
					break;

				/* Fill in the event IP.  Our users will need
				 * them to make sense of the PTWRITE payload.
				 */
				ev->variant.ptwrite.ip = decoder->ip;
				ev->ip_suppressed = 0;
			} else {
				/* The ptwrite event contains the IP of the
				 * ptwrite instruction.  We could have processed
				 * it already in process_events_before() but
				 * this would have required preserving the event
				 * indication already from there.
				 *
				 * It's easier to handle this case here, as
				 * well.
				 */
				if (decoder->ip != ev->variant.ptwrite.ip)
					break;
			}

			/* We decoded the PTWRITE instruction into @insn/@iext;
			 * @decoder->ip still points to it.
			 *
			 * Determine the next IP - this shouldn't require trace.
			 */
			status = pt_insn_next_ip(&decoder->ip, insn, iext);
			if (status < 0)
				return status;

			return pt_insn_status(decoder, pts_event_pending);
		}

		/* If we fall out of the switch, we're done. */
		break;
	}

	return pt_insn_status(decoder, 0);
}

enum {
	/* The maximum number of steps to take when determining whether the
	 * event location can be reached.
	 */
	bdm64_max_steps	= 0x100
};

/* Try to work around erratum BDM64.
 *
 * If we got a transaction abort immediately following a branch that produced
 * trace, the trace for that branch might have been corrupted.
 *
 * Returns a positive integer if the erratum was handled.
 * Returns zero if the erratum does not seem to apply.
 * Returns a negative error code otherwise.
 */
static int handle_erratum_bdm64(struct pt_insn_decoder *decoder,
				const struct pt_event *ev,
				const struct pt_insn *insn,
				const struct pt_insn_ext *iext)
{
	int status;

	if (!decoder || !ev || !insn || !iext)
		return -pte_internal;

	/* This only affects aborts. */
	if (!ev->variant.tsx.aborted)
		return 0;

	/* This only affects branches. */
	if (!pt_insn_is_branch(insn, iext))
		return 0;

	/* Let's check if we can reach the event location from here.
	 *
	 * If we can, let's assume the erratum did not hit.  We might still be
	 * wrong but we're not able to tell.
	 */
	status = pt_insn_range_is_contiguous(decoder->ip, ev->variant.tsx.ip,
					     decoder->mode, decoder->image,
					     &decoder->asid, bdm64_max_steps);
	if (status > 0)
		return 0;

	/* We can't reach the event location.  This could either mean that we
	 * stopped too early (and status is zero) or that the erratum hit.
	 *
	 * We assume the latter and pretend that the previous branch brought us
	 * to the event location, instead.
	 */
	decoder->ip = ev->variant.tsx.ip;

	return 1;
}

/* Check whether a peek TSX event should be postponed.
 *
 * This involves handling erratum BDM64.
 *
 * Returns a positive integer if the event is to be postponed.
 * Returns zero if the event should be processed.
 * Returns a negative error code otherwise.
 */
static inline int pt_insn_postpone_peek_tsx(struct pt_insn_decoder *decoder,
					    const struct pt_insn *insn,
					    const struct pt_insn_ext *iext,
					    const struct pt_event *ev)
{
	int status;

	if (!decoder || !ev)
		return -pte_internal;

	if (ev->ip_suppressed)
		return 0;

	if (insn && iext && decoder->query.config.errata.bdm64) {
		status = handle_erratum_bdm64(decoder, ev, insn, iext);
		if (status < 0)
			return status;
	}

	if (decoder->ip != ev->variant.tsx.ip)
		return 1;

	return 0;
}

static int process_events_peek(struct pt_insn_decoder *decoder,
			       struct pt_insn *insn,
			       const struct pt_insn_ext *iext)
{
	if (!decoder)
		return -pte_internal;

	for (;;) {
		struct pt_event *ev;
		int status;

		status = event_pending(decoder);
		if (status <= 0) {
			if (status < 0)
				return status;

			break;
		}

		ev = &decoder->event;
		switch (ev->type) {
		case ptev_disabled:
			break;

		case ptev_enabled:
			return pt_insn_status(decoder, pts_event_pending);

		case ptev_async_disabled:
			if (ev->variant.async_disabled.at != decoder->ip)
				break;

			if (decoder->query.config.errata.skd022) {
				int errcode;

				errcode = handle_erratum_skd022(decoder);
				if (errcode != 0) {
					if (errcode < 0)
						return errcode;

					/* If the erratum applies, we postpone
					 * the modified event to the next call
					 * to pt_insn_next().
					 */
					break;
				}
			}

			decoder->last_disable_ip = decoder->ip;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_tsx:
			status = pt_insn_postpone_peek_tsx(decoder, insn, iext,
							   ev);
			if (status != 0) {
				if (status < 0)
					return status;

				break;
			}

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_async_branch:
			if (ev->variant.async_branch.from != decoder->ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_overflow:
			return pt_insn_status(decoder, pts_event_pending);

		case ptev_exec_mode:
			if (!ev->ip_suppressed &&
			    ev->variant.exec_mode.ip != decoder->ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_paging:
			if (decoder->enabled)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_async_paging:
			if (!ev->ip_suppressed &&
			    ev->variant.async_paging.ip != decoder->ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_vmcs:
			if (decoder->enabled)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_async_vmcs:
			if (!ev->ip_suppressed &&
			    ev->variant.async_vmcs.ip != decoder->ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_stop:
			return pt_insn_status(decoder, pts_event_pending);

		case ptev_exstop:
			if (!ev->ip_suppressed && decoder->enabled &&
			    decoder->ip != ev->variant.exstop.ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_mwait:
			if (!ev->ip_suppressed && decoder->enabled &&
			    decoder->ip != ev->variant.mwait.ip)
				break;

			return pt_insn_status(decoder, pts_event_pending);

		case ptev_pwre:
		case ptev_pwrx:
			return pt_insn_status(decoder, pts_event_pending);

		case ptev_ptwrite:
			/* The event is reported after the corresponding PTWRITE
			 * instruction and indicated in process_events_after().
			 *
			 * Any subsequent ptwrite event binds to a different
			 * instruction and must wait until the next iteration -
			 * as long as tracing is enabled.
			 *
			 * When tracing is disabled, we forward all ptwrite
			 * events immediately to the user.
			 */
			if (decoder->enabled)
				break;

			return pt_insn_status(decoder, pts_event_pending);
		}

		/* If we fall out of the switch, we're done. */
		break;
	}

	return pt_insn_status(decoder, 0);
}

static inline int insn_to_user(struct pt_insn *uinsn, size_t size,
			       const struct pt_insn *insn)
{
	if (!uinsn || !insn)
		return -pte_internal;

	if (uinsn == insn)
		return 0;

	/* Zero out any unknown bytes. */
	if (sizeof(*insn) < size) {
		memset(uinsn + sizeof(*insn), 0, size - sizeof(*insn));

		size = sizeof(*insn);
	}

	memcpy(uinsn, insn, size);

	return 0;
}

int pt_insn_next(struct pt_insn_decoder *decoder, struct pt_insn *uinsn,
		 size_t size)
{
	struct pt_insn_ext iext;
	struct pt_insn insn, *pinsn;
	int status, errcode;

	if (!uinsn || !decoder)
		return -pte_invalid;

	/* Tracing must be enabled.
	 *
	 * If it isn't we should be processing events until we either run out of
	 * trace or process a tracing enabled event.
	 */
	if (!decoder->enabled) {
		if (decoder->status & pts_eos)
			return -pte_eos;

		return -pte_no_enable;
	}

	pinsn = size == sizeof(insn) ? uinsn : &insn;

	/* Zero-initialize the instruction in case of error returns. */
	memset(pinsn, 0, sizeof(*pinsn));

	/* We process events three times:
	 * - once based on the current IP.
	 * - once based on the instruction at that IP.
	 * - once based on the next IP.
	 *
	 * Between the first and second round of event processing, we decode
	 * the instruction and fill in @insn.
	 *
	 * This is necessary to attribute events to the correct instruction.
	 */
	errcode = process_events_before(decoder, pinsn);
	if (errcode < 0)
		goto err;

	/* Decode the current instruction. */
	if (decoder->speculative)
		pinsn->speculative = 1;
	pinsn->ip = decoder->ip;
	pinsn->mode = decoder->mode;

	errcode = pt_insn_decode(pinsn, &iext, decoder->image, &decoder->asid);
	if (errcode < 0)
		goto err;

	/* After decoding the instruction, we must not change the IP in this
	 * iteration - postpone processing of events that would to the next
	 * iteration.
	 */
	decoder->event_may_change_ip = 0;

	/* We may already indicate user-relevant events, here.  We will ignore
	 * all other status bits.
	 */
	status = process_events_after(decoder, pinsn, &iext);
	if (status < 0) {
		errcode = status;
		goto err;
	}

	/* We're done if we already have a user-event indicated.
	 *
	 * Event processing takes care to proceed past the eventing instruction.
	 */
	if (!(status & pts_event_pending)) {
		/* Determine the next instruction's IP so we can indicate async
		 * disable events already in this instruction.
		 *
		 * This only makes sense as long as tracing is enabled, of
		 * course.  If it isn't, we're either done or we will process
		 * the corresponding enabled event in the next iteration.
		 */
		if (decoder->enabled) {
			/* Proceed errors are signaled one instruction too
			 * early.
			 */
			errcode = pt_insn_proceed(decoder, pinsn, &iext);
			if (errcode < 0)
				goto err;
		}

		/* Peek at events for the next IP.  Some will be indicated
		 * already in @pinsn.
		 */
		status = process_events_peek(decoder, pinsn, &iext);
		if (status < 0) {
			errcode = status;
			goto err;
		}
	}

	errcode = insn_to_user(uinsn, size, pinsn);
	if (errcode < 0)
		return errcode;

	/* We're done with this instruction.  Now we may change the IP again. */
	decoder->event_may_change_ip = 1;

	return status;

err:
	/* We provide the (incomplete) instruction also in case of errors.
	 *
	 * For decode or post-decode event-processing errors, the IP or
	 * other fields are already valid and may help diagnose the error.
	 */
	(void) insn_to_user(uinsn, size, pinsn);

	return errcode;
}

int pt_insn_event(struct pt_insn_decoder *decoder, struct pt_event *uevent,
		  size_t size)
{
	struct pt_event *ev;
	int status;

	if (!decoder || !uevent)
		return -pte_invalid;

	/* We must currently process an event. */
	if (!decoder->process_event)
		return -pte_bad_query;

	ev = &decoder->event;
	switch (ev->type) {
	default:
		/* This is not a user event.
		 *
		 * We either indicated it wrongly or the user called
		 * pt_insn_event() without a pts_event_pending indication.
		 */
		return -pte_bad_query;

	case ptev_enabled:
		/* Indicate that tracing resumes from the IP at which tracing
		 * had been disabled before (with some special treatment for
		 * calls).
		 */
		if (decoder->last_disable_ip == ev->variant.enabled.ip)
			ev->variant.enabled.resumed = 1;

		status = pt_insn_process_enabled(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_async_disabled:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_disabled.at)
			return -pte_bad_query;

		/* Fall through. */
	case ptev_disabled:
		status = pt_insn_process_disabled(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_async_branch:
		if (decoder->ip != ev->variant.async_branch.from)
			return -pte_bad_query;

		status = pt_insn_process_async_branch(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_async_paging:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_paging.ip)
			return -pte_bad_query;

		/* Fall through. */
	case ptev_paging:
		status = pt_insn_process_paging(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_async_vmcs:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_vmcs.ip)
			return -pte_bad_query;

		/* Fall through. */
	case ptev_vmcs:
		status = pt_insn_process_vmcs(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_overflow:
		status = pt_insn_process_overflow(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_exec_mode:
		status = pt_insn_process_exec_mode(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_tsx:
		status = pt_insn_process_tsx(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_stop:
		status = pt_insn_process_stop(decoder);
		if (status < 0)
			return status;

		break;

	case ptev_exstop:
		if (!ev->ip_suppressed && decoder->enabled &&
		    decoder->ip != ev->variant.exstop.ip)
			return -pte_bad_query;

		break;

	case ptev_mwait:
		if (!ev->ip_suppressed && decoder->enabled &&
		    decoder->ip != ev->variant.mwait.ip)
			return -pte_bad_query;

		break;

	case ptev_pwre:
	case ptev_pwrx:
	case ptev_ptwrite:
		break;
	}

	/* Copy the event to the user.  Make sure we're not writing beyond the
	 * memory provided by the user.
	 *
	 * We might truncate details of an event but only for those events the
	 * user can't know about, anyway.
	 */
	if (sizeof(*ev) < size)
		size = sizeof(*ev);

	memcpy(uevent, ev, size);

	/* This completes processing of the current event. */
	decoder->process_event = 0;

	/* Indicate further events. */
	return process_events_peek(decoder, NULL, NULL);
}
