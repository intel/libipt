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
#include "pt_compiler.h"

#include "intel-pt.h"

#include <string.h>
#include <stdlib.h>


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

	return 0;
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

static int process_enabled_event(struct pt_insn_decoder *decoder,
				 struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder || !insn)
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

	/* Delay processing of the event if we can't change the IP. */
	if (!decoder->event_may_change_ip)
		return 0;

	decoder->ip = ev->variant.enabled.ip;
	decoder->enabled = 1;

	/* Clear an indication of a preceding disable on the same
	 * instruction.
	 */
	insn->disabled = 0;

	/* Check if we resumed from a preceding disable or if we enabled at a
	 * different position.
	 * Should we ever get more than one enabled event, enabled wins.
	 */
	if (decoder->last_disable_ip == decoder->ip && !insn->enabled)
		insn->resumed = 1;
	else {
		insn->enabled = 1;
		insn->resumed = 0;
	}

	return 1;
}

static int process_disabled_event(struct pt_insn_decoder *decoder,
				  struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder || !insn)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	decoder->enabled = 0;
	insn->disabled = 1;

	return 1;
}

static int process_async_disabled_event(struct pt_insn_decoder *decoder,
					struct pt_insn *insn)
{
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = process_disabled_event(decoder, insn);
	if (errcode <= 0)
		return errcode;

	decoder->last_disable_ip = decoder->ip;

	return errcode;
}

static int process_sync_disabled_event(struct pt_insn_decoder *decoder,
				       struct pt_insn *insn,
				       const struct pt_insn_ext *iext)
{
	int errcode, iperr;

	if (!decoder || !insn)
		return -pte_internal;

	errcode = process_disabled_event(decoder, insn);
	if (errcode <= 0)
		return errcode;

	iperr = pt_insn_next_ip(&decoder->last_disable_ip, insn, iext);
	if (iperr < 0) {
		/* We don't know the IP on error. */
		decoder->last_disable_ip = 0ull;

		/* For indirect calls, assume that we return to the next
		 * instruction.
		 */
		if (iperr == -pte_bad_query) {
			switch (insn->iclass) {
			case ptic_call:
			case ptic_far_call:
				/* We only check the instruction class, not the
				 * is_direct property, since direct calls would
				 * have been handled by pt_insn_nex_ip() or
				 * would have provoked a different error.
				 */
				decoder->last_disable_ip =
					insn->ip + insn->size;
				break;

			default:
				break;
			}
		}
	}

	return errcode;
}

static int process_async_branch_event(struct pt_insn_decoder *decoder)
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

	return 1;
}

static int process_paging_event(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	decoder->asid.cr3 = ev->variant.paging.cr3;

	return 1;
}

static int process_overflow_event(struct pt_insn_decoder *decoder,
				  struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder || !insn)
		return -pte_internal;

	ev = &decoder->event;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* Delay processing of the event if we can't change the IP. */
	if (!decoder->event_may_change_ip)
		return 0;

	/* We don't know the TSX state.  Let's assume we execute normally.
	 *
	 * We also don't know the execution mode.  Let's keep what we have
	 * in case we don't get an update before we have to decode the next
	 * instruction.
	 */
	decoder->speculative = 0;

	/* Disable tracing if we don't have an IP. */
	if (ev->ip_suppressed) {
		/* Indicate the overflow in case tracing was enabled before.
		 *
		 * If tracing was disabled, we're not really resyncing.
		 */
		if (decoder->enabled) {
			decoder->enabled = 0;

			/* We mark the instruction as resynced.  It won't be
			 * returned unless we enable tracing again, in which
			 * case this is the labeling we want.
			 */
			insn->resynced = 1;
		}
	} else {
		/* Jump to the IP at which the overflow was resolved. */
		decoder->ip = ev->variant.overflow.ip;
		decoder->enabled = 1;

		insn->resynced = 1;
	}

	return 1;
}

static int process_exec_mode_event(struct pt_insn_decoder *decoder)
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

	return 1;
}

static int process_tsx_event(struct pt_insn_decoder *decoder,
			     struct pt_insn *insn)
{
	struct pt_event *ev;
	int old_speculative;

	if (!decoder)
		return -pte_internal;

	old_speculative = decoder->speculative;
	ev = &decoder->event;

	decoder->speculative = ev->variant.tsx.speculative;

	if (insn && decoder->enabled) {
		if (ev->variant.tsx.aborted)
			insn->aborted = 1;
		else if (old_speculative && !ev->variant.tsx.speculative)
			insn->committed = 1;
	}

	return 1;
}

static int process_stop_event(struct pt_insn_decoder *decoder,
			      struct pt_insn *insn)
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

	if (insn)
		insn->stopped = 1;

	return 1;
}

static int process_vmcs_event(struct pt_insn_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	decoder->asid.vmcs = ev->variant.vmcs.base;

	return 1;
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
		return process_enabled_event(decoder, insn);

	case ptev_async_branch:
		if (ev->variant.async_branch.from == decoder->ip)
			return process_async_branch_event(decoder);

		return 0;

	case ptev_async_disabled:
		/* We would normally process the disabled event when peeking
		 * at the next instruction in order to indicate the disabling
		 * properly.
		 * This is to catch the case where we disable tracing before
		 * we actually started.
		 */
		if (ev->variant.async_disabled.at == decoder->ip) {
			if (decoder->query.config.errata.skd022) {
				int errcode;

				errcode = handle_erratum_skd022(decoder);
				if (errcode < 0)
					return errcode;

				if (errcode)
					return 0;
			}

			return process_async_disabled_event(decoder, insn);
		}

		return 0;

	case ptev_async_paging:
		if (ev->ip_suppressed ||
		    ev->variant.async_paging.ip == decoder->ip)
			return process_paging_event(decoder);

		return 0;

	case ptev_async_vmcs:
		if (ev->ip_suppressed ||
		    ev->variant.async_vmcs.ip == decoder->ip)
			return process_vmcs_event(decoder);

		return 0;

	case ptev_disabled:
		return 0;

	case ptev_paging:
		if (!decoder->enabled)
			return process_paging_event(decoder);

		return 0;

	case ptev_vmcs:
		if (!decoder->enabled)
			return process_vmcs_event(decoder);

		return 0;

	case ptev_overflow:
		return process_overflow_event(decoder, insn);

	case ptev_exec_mode:
		if (ev->ip_suppressed ||
		    ev->variant.exec_mode.ip == decoder->ip)
			return process_exec_mode_event(decoder);

		return 0;

	case ptev_tsx:
		/* We would normally process the tsx event when peeking
		 * at the next instruction in order to indicate commits
		 * and aborts properly.
		 * This is to catch the case where we just sync'ed.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.tsx.ip == decoder->ip)
			return process_tsx_event(decoder, NULL);

		return 0;

	case ptev_stop:
		/* We would normally process the stop event when peeking at
		 * the next instruction in order to indicate the stop
		 * properly.
		 * This is to catch the case where we stop before we actually
		 * started.
		 */
		return process_stop_event(decoder, NULL);
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

static int pt_insn_skl014(const struct pt_insn *insn,
			  const struct pt_insn_ext *iext)
{
	if (!insn || !iext)
		return 0;

	switch (insn->iclass) {
	default:
		return 0;

	case ptic_call:
	case ptic_jump:
		return iext->variant.branch.is_direct;
	}
}

static int process_one_event_after(struct pt_insn_decoder *decoder,
				   struct pt_insn *insn,
				   const struct pt_insn_ext *iext)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

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
		/* We will process those events on the next iteration. */
		return 0;

	case ptev_disabled:
		if (ev->ip_suppressed) {
			if (pt_insn_is_far_branch(insn, iext) ||
			    pt_insn_changes_cpl(insn, iext) ||
			    pt_insn_changes_cr3(insn, iext))
				return process_sync_disabled_event(decoder,
								   insn, iext);

			if (decoder->query.config.errata.skl014 &&
			    pt_insn_skl014(insn, iext))
				return process_sync_disabled_event(decoder,
								   insn, iext);
		} else {
			switch (insn->iclass) {
			case ptic_other:
				break;

			case ptic_call:
			case ptic_jump:
				/* If we got an IP with the disabled event, we
				 * may ignore direct branches that go to a
				 * different IP.
				 */
				if (iext->variant.branch.is_direct) {
					uint64_t ip;

					ip = insn->ip;
					ip += insn->size;
					ip += iext->variant.branch.displacement;

					if (ip != ev->variant.disabled.ip)
						break;
				}

				fallthrough;
			case ptic_return:
			case ptic_far_call:
			case ptic_far_return:
			case ptic_far_jump:
			case ptic_cond_jump:
				return process_sync_disabled_event(decoder,
								   insn, iext);

			case ptic_error:
				return -pte_bad_insn;
			}
		}

		return 0;

	case ptev_paging:
		if (pt_insn_binds_to_pip(insn, iext) &&
		    !decoder->paging_event_bound) {
			/* Each instruction only binds to one paging event. */
			decoder->paging_event_bound = 1;

			return process_paging_event(decoder);
		}

		return 0;

	case ptev_vmcs:
		if (pt_insn_binds_to_vmcs(insn, iext) &&
		    !decoder->vmcs_event_bound) {
			/* Each instruction only binds to one vmcs event. */
			decoder->vmcs_event_bound = 1;

			return process_vmcs_event(decoder);
		}

		return 0;
	}

	return -pte_internal;
}

static int process_events_after(struct pt_insn_decoder *decoder,
				struct pt_insn *insn,
				const struct pt_insn_ext *iext)
{
	int pending, processed, errcode;

	if (!decoder || !insn)
		return -pte_internal;

	pending = event_pending(decoder);
	if (pending <= 0)
		return pending;

	decoder->paging_event_bound = 0;
	decoder->vmcs_event_bound = 0;

	for (;;) {
		processed = process_one_event_after(decoder, insn, iext);
		if (processed < 0)
			return processed;

		if (!processed)
			return 0;

		decoder->process_event = 0;

		errcode = process_events_before(decoder, insn);
		if (errcode < 0)
			return errcode;

		pending = event_pending(decoder);
		if (pending <= 0)
			return pending;
	}
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

static int process_one_event_peek(struct pt_insn_decoder *decoder,
				  struct pt_insn *insn,
				  const struct pt_insn_ext *iext)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_async_disabled:
		if (ev->variant.async_disabled.at == decoder->ip) {
			if (decoder->query.config.errata.skd022) {
				int errcode;

				errcode = handle_erratum_skd022(decoder);
				if (errcode < 0)
					return errcode;

				if (errcode)
					return 0;
			}

			return process_async_disabled_event(decoder, insn);
		}

		return 0;

	case ptev_tsx:
		if (decoder->query.config.errata.bdm64) {
			int errcode;

			errcode = handle_erratum_bdm64(decoder, ev, insn, iext);
			if (errcode < 0)
				return errcode;
		}

		if (ev->ip_suppressed ||
		    ev->variant.tsx.ip == decoder->ip)
			return process_tsx_event(decoder, insn);

		return 0;

	case ptev_async_branch:
		/* We indicate the interrupt in the preceding instruction.
		 */
		if (ev->variant.async_branch.from == decoder->ip) {
			insn->interrupted = 1;

			return process_async_branch_event(decoder);
		}

		return 0;

	case ptev_enabled:
	case ptev_overflow:
	case ptev_disabled:
	case ptev_paging:
	case ptev_vmcs:
		return 0;

	case ptev_exec_mode:
		/* We would normally process this event in the next iteration.
		 *
		 * We process it here, as well, in case we have a peek event
		 * hiding behind.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.exec_mode.ip == decoder->ip)
			return process_exec_mode_event(decoder);

		return 0;

	case ptev_async_paging:
		/* We would normally process this event in the next iteration.
		 *
		 * We process it here, as well, in case we have a peek event
		 * hiding behind.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.async_paging.ip == decoder->ip)
			return process_paging_event(decoder);

		return 0;

	case ptev_async_vmcs:
		/* We would normally process this event in the next iteration.
		 *
		 * We process it here, as well, in case we have a peek event
		 * hiding behind.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.async_vmcs.ip == decoder->ip)
			return process_vmcs_event(decoder);

		return 0;

	case ptev_stop:
		return process_stop_event(decoder, insn);
	}

	return -pte_internal;
}

static int process_events_peek(struct pt_insn_decoder *decoder,
			       struct pt_insn *insn,
			       const struct pt_insn_ext *iext)
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

		processed = process_one_event_peek(decoder, insn, iext);
		if (processed < 0)
			return processed;

		if (!processed)
			break;

		decoder->process_event = 0;
	}

	return 0;
}

static int proceed(struct pt_insn_decoder *decoder, const struct pt_insn *insn,
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

static int pt_insn_status(const struct pt_insn_decoder *decoder)
{
	int status, flags;

	if (!decoder)
		return -pte_internal;

	status = decoder->status;
	flags = 0;

	/* Forward end-of-trace indications.
	 *
	 * Postpone it as long as we're still processing events, though.
	 */
	if ((status & pts_eos) && !decoder->process_event)
		flags |= pts_eos;

	return flags;
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
	int errcode;

	if (!uinsn || !decoder)
		return -pte_invalid;

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

	/* If tracing is disabled at this point, we should be at the end
	 * of the trace - otherwise there should have been a re-enable
	 * event.
	 */
	if (!decoder->enabled) {
		struct pt_event event;

		/* Any query should give us an end of stream, error. */
		errcode = pt_qry_event(&decoder->query, &event, sizeof(event));
		if (errcode != -pte_eos)
			errcode = -pte_no_enable;

		goto err;
	}

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

	errcode = process_events_after(decoder, pinsn, &iext);
	if (errcode < 0)
		goto err;

	/* If event processing disabled tracing, we're done for this
	 * iteration - we will process the re-enable event on the next.
	 *
	 * Otherwise, we determine the next instruction and peek ahead.
	 *
	 * This may indicate an event already in this instruction.
	 */
	if (decoder->enabled) {
		/* Proceed errors are signaled one instruction too early. */
		errcode = proceed(decoder, pinsn, &iext);
		if (errcode < 0)
			goto err;

		/* Peek errors are ignored.  We will run into them again
		 * in the next iteration.
		 */
		(void) process_events_peek(decoder, pinsn, &iext);
	}

	errcode = insn_to_user(uinsn, size, pinsn);
	if (errcode < 0)
		return errcode;

	/* We're done with this instruction.  Now we may change the IP again. */
	decoder->event_may_change_ip = 1;

	return pt_insn_status(decoder);

err:
	/* We provide the (incomplete) instruction also in case of errors.
	 *
	 * For decode or post-decode event-processing errors, the IP or
	 * other fields are already valid and may help diagnose the error.
	 */
	(void) insn_to_user(uinsn, size, pinsn);

	return errcode;
}
