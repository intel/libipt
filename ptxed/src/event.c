/*
 * Copyright (c) 2013, Intel Corporation
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

#include "event.h"
#include "disas.h"
#include "decode.h"

#include "pt_decode.h"


static int do_proceed_to_event(struct disas_state *state)
{
	struct pt_event *ev;

	ev = &state->event;

	switch (ev->type) {
	case ptev_disabled: {
		int status;

		if (ev->ip_suppressed)
			status = proceed_to_inst(state, disas_inst_changes_cpl);
		else
			status = proceed_to_ip(state, ev->variant.disabled.ip);

		/* Our search for the event location will likely fail. */
		switch (pt_errcode(status)) {
		case pte_bad_query:
			/* We proceeded as far as we can - re-sync at enable. */
			return 0;

		case pte_eos:
			/* The trace stream ended with disable. Make sure to
			 * process the event before we terminate.
			 */
			(void) process_event(state);
			return status;

		default:
			return status;
		}
	}

	case ptev_async_disabled:
		return proceed_to_ip(state, ev->variant.async_disabled.at);

	case ptev_async_branch:
		return proceed_to_ip(state, ev->variant.async_branch.from);

	case ptev_paging:
		/* For status update events, we stay where we are. */
		if (ev->status_update)
			return 0;

		return proceed_to_inst(state, disas_inst_changes_cr3);

	case ptev_async_paging:
		/* We stay where we are if we don't have enough information.
		 *
		 * Since the paging event is asynchronous, we probably are
		 * already at the correct location.
		 */
		if (ev->ip_suppressed)
			return 0;

		return proceed_to_ip(state, ev->variant.async_paging.ip);

	case ptev_enabled:
	case ptev_overflow:
		/* We need to re-sync before we may proceed. */
		return 0;

	case ptev_exec_mode:
		/* The IP must not be suppressed. */
		if (ev->ip_suppressed) {
			/* For status update events, we stay where we are. */
			if (ev->status_update)
				return 0;

			return -pte_bad_packet;
		}

		return proceed_to_ip(state, ev->variant.exec_mode.ip);

	case ptev_tsx:
		/* The IP may be suppressed for this event. In that case, we
		 * only note the tsx event.
		 */
		if (ev->ip_suppressed)
			return 0;

		return proceed_to_ip(state, ev->variant.tsx.ip);
	}

	/* We should not get here. */
	return -pte_internal;
}

int proceed_to_event(struct disas_state *state)
{
	int flags, status;

	flags = state->flags;

	/* While tracing is disabled, we remain at the current location. */
	if (flags & pf_pt_disabled)
		return 0;

	state->flags |= pf_ignore_events;

	status = do_proceed_to_event(state);

	state->flags = flags;

	return status;
}

int process_event(struct disas_state *state)
{
	struct pt_event *ev;

	ev = &state->event;

	switch (ev->type) {
	case ptev_enabled:
		/* This event can't be a status update. */
		if (ev->status_update)
			return -pte_bad_packet;

		printf("[enabled]\n");

		state->flags &= ~pf_pt_disabled;

		/* We cannot resync if there is no ip. */
		if (ev->ip_suppressed)
			return -pte_bad_packet;

		state->ip = ev->variant.enabled.ip;
		break;

	case ptev_disabled:
	case ptev_async_disabled:
		/* This event can't be a status update. */
		if (ev->status_update)
			return -pte_bad_packet;

		state->flags |= pf_pt_disabled;
		printf("[disabled]\n");
		break;

	case ptev_async_branch:
		/* This event can't be a status update. */
		if (ev->status_update)
			return -pte_bad_packet;

		printf("[interrupt]\n");

		state->ip = ev->variant.async_branch.to;
		break;

	case ptev_paging:
	case ptev_async_paging:
		/* We do not support paging. */
		break;

	case ptev_overflow:
		/* This event can't be a status update. */
		if (ev->status_update)
			return -pte_bad_packet;

		printf("[overflow]\n");

		/* We cannot resync if there is no ip. */
		if (ev->ip_suppressed)
			return -pte_bad_packet;

		/* Re-syncing. */
		state->ip = ev->variant.overflow.ip;
		break;

	case ptev_exec_mode: {
		enum pt_exec_mode mode;

		mode = ev->variant.exec_mode.mode;
		if (ev->status_update) {
			int errcode;

			errcode = disas_check_exec_mode(state, mode);
			if (errcode < 0)
				return errcode;

			if (!errcode)
				break;

			(void) diag("warning: execution mode mismatch",
				    state, pte_internal);
		}

		disas_set_exec_mode(state, mode);
	}
		break;

	case ptev_tsx: {
		int mode;

		mode = ev->variant.tsx.speculative;
		if (ev->status_update) {
			int errcode;

			errcode = disas_check_speculation_mode(state, mode);
			if (errcode < 0)
				return errcode;

			if (!errcode)
				break;

			(void) diag("warning: speculation mode mismatch",
				    state, pte_internal);
		}

		disas_set_speculation_mode(state, mode);

		if (ev->variant.tsx.aborted)
			printf("[aborted]\n");
	}
		break;
	}

	return 0;
}
