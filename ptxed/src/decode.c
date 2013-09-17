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

#include "decode.h"
#include "disas.h"
#include "event.h"

#include "pt_decode.h"
#include "pt_error.h"

#include <xed-decode.h>
#include <inttypes.h>

static void print_inst(struct disas_state *state)
{
	static int suppressed;

	if (disas_is_suppressed(state->ip)) {
		if (!suppressed)
			printf("[suppressed]\n");

		suppressed = 1;
	} else {
		if (state->flags & pf_speculative)
			printf("? ");

		(void)disas_print_inst(state);

		printf("\n");

		suppressed = 0;
	}
}

static int proceed_cond_branch(struct disas_state *state)
{
	int taken, status;

	status = pt_query_cond_branch(state->decoder, &taken);
	if (status < 0)
		return status;

	if (taken)
		state->ip +=
			xed_decoded_inst_get_branch_displacement(&state->inst);

	return status;
}

static int proceed_indir_branch(struct disas_state *state)
{
	return pt_query_uncond_branch(state->decoder, &state->ip);
}

static int proceed_dir_branch(struct disas_state *state)
{
	state->ip +=
		xed_decoded_inst_get_branch_displacement(&state->inst);

	return 0;
}

static int proceed_call(struct disas_state *state)
{
	int status, errcode;
	uint64_t nip;

	/* State points to the instruction following the call. */
	nip = state->ip;

	switch (xed_decoded_inst_get_iform_enum(&state->inst)) {
	default:
		/* We skip too many cases to benefit from the compiler's
		 * switch case checking.
		 */
		return diag("bad call", state, pte_nosync);

	case XED_IFORM_CALL_NEAR_RELBRd:
	case XED_IFORM_CALL_NEAR_RELBRz:
		status = proceed_dir_branch(state);
		if (status < 0)
			return status;

		/* Direct calls to the next address as used for PIC do not
		 * participate in ret compression.
		 */
		if (state->ip != nip) {
			errcode = disas_push_call(state, nip);
			if (errcode < 0)
				return errcode;
		}

		return status;

	case XED_IFORM_CALL_NEAR_GPRv:
	case XED_IFORM_CALL_NEAR_MEMv:
		status = proceed_indir_branch(state);
		if (status < 0)
			return status;

		errcode = disas_push_call(state, nip);
		if (errcode < 0)
			return errcode;

		return status;

	case XED_IFORM_CALL_FAR_MEMp2:
	case XED_IFORM_CALL_FAR_PTRp_IMMw:
		/* Only near calls participate in ret compression. */
		return proceed_indir_branch(state);
	}
}

static int proceed_ret(struct disas_state *state)
{
	if (state->flags & pf_ptev_compression) {
		int status, taken, errcode;

		status = pt_query_cond_branch(state->decoder, &taken);
		if (status >= 0) {
			/* If the branch is not taken, we got out of sync. */
			if (!taken)
				return diag("bad ret tnt", state, pte_nosync);

			errcode = disas_pop_call(state);
			if (errcode < 0)
				return errcode;

			return status;
		}
	}

	return proceed_indir_branch(state);
}

/* Execute the previously decoded instruction.
 *
 * We use XED directly to avoid duplicate decodings.
 *
 * Returns a pt_status_flag bit-vector on success.
 * Returns a negative error code otherwise.
 */
static int execute(struct disas_state *state)
{
	int bytes;

	bytes = disas_get_inst_size(state);

	/* Branches are relative to the next instruction. */
	state->ip += bytes;

	switch (xed_decoded_inst_get_category(&state->inst)) {
	default:
		return 0;

	case XED_CATEGORY_COND_BR:
		return proceed_cond_branch(state);

	case XED_CATEGORY_UNCOND_BR:
		switch (xed_decoded_inst_get_iform_enum(&state->inst)) {
		default:
			/* We skip too many cases to benefit from the compiler's
			 * switch case checking.
			 */
			return diag("bad br", state, pte_nosync);

		case XED_IFORM_JMP_RELBRb:
		case XED_IFORM_JMP_RELBRd:
		case XED_IFORM_JMP_RELBRz:
			return proceed_dir_branch(state);

		case XED_IFORM_JMP_GPRv:
		case XED_IFORM_JMP_MEMv:
		case XED_IFORM_JMP_FAR_MEMp:
		case XED_IFORM_JMP_FAR_PTRp_IMMw:
			return proceed_indir_branch(state);
		}

	case XED_CATEGORY_CALL:
		return proceed_call(state);

	case XED_CATEGORY_RET:
		return proceed_ret(state);

	case XED_CATEGORY_INTERRUPT:
		switch (xed_decoded_inst_get_iform_enum(&state->inst)) {
		default:
			/* We skip too many cases to benefit from the compiler's
			 * switch case checking.
			 */
			return -pte_nosync;

		case XED_IFORM_INT_IMMb:
		case XED_IFORM_INT1:
		case XED_IFORM_INT3:
		case XED_IFORM_INTO:
			/* Interrupts do not participate in ret compression.
			 *
			 * The fact that we're asked to execute an interrupt
			 * indicates that we're not filtering ring 0. Otherwise,
			 * the instruction would have been represented as
			 * disable event and we would take a different route.
			 */
			return proceed_indir_branch(state);
		}

	case XED_CATEGORY_SYSCALL:
	case XED_CATEGORY_SYSRET:
	case XED_CATEGORY_SYSTEM:
		/* System call and return do not participate in ret compression.
		 *
		 * The fact that we're asked to execute a syscall or sysret
		 * indicates that we're not filtering ring 0. Otherwise, the
		 * instruction would have been represented as disable event
		 * and we would take a different route.
		 */
		return proceed_indir_branch(state);
	}
}

int proceed(struct disas_state *state)
{
	int errcode;

	errcode = disas_decode_inst(state);
	if (errcode < 0)
		return errcode;

	print_inst(state);

	return execute(state);
}

int proceed_to_ip(struct disas_state *state, uint64_t ip)
{
	int status = 0;

	while (state->ip != ip) {
		status = proceed(state);
		if (status) {
			if (status < 0)
				return status;

			/* Stop as soon as an event is signaled, unless we are
			 * configured to ignore events.
			 */
			if (status & pts_event_pending)
				if (!(state->flags & pf_ignore_events))
					return status;

			/* The pending event will be signaled on each iteration
			 * from now on, until we query it.
			 */
		}
	}

	return status;
}

int proceed_to_inst(struct disas_state *state,
		    int (*pred)(struct disas_state *))
{
	int status = 0;

	for (;;) {
		int errcode, found;

		errcode = disas_decode_inst(state);
		if (errcode < 0)
			return errcode;

		found = pred(state);
		if (found < 0)
			return found;

		if (found)
			break;

		print_inst(state);

		status = execute(state);
		if (status) {
			if (status < 0)
				return status;

			/* Stop as soon as an event is signaled, unless we are
			 * configured to ignore events.
			 */
			if (status & pts_event_pending)
				if (!(state->flags & pf_ignore_events))
					return status;

			/* The pending event will be signaled on each iteration
			 * from now on, until we query it.
			 */
		}
	}

	return status;
}

/* Process all pending events and proceed to the event locations.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
static int process_pending_events(struct disas_state *state, int status)
{
	for (;;) {
		int errcode;

		if (!(status & pts_event_pending))
			break;

		status = pt_query_event(state->decoder, &state->event);
		if (status < 0)
			return status;

		errcode = proceed_to_event(state, status);
		if (errcode < 0)
			return errcode;

		errcode = process_event(state, status);
		if (errcode < 0)
			return errcode;
	}

	return 0;
}

/* Process initial events after syncing the decoder.
 *
 * Initially, we expect a series of status update events.  Since we haven't
 * initialized our internal state, yet, use those events to do so.
 *
 * After the initial status update, we continue to process events normally.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
static int process_initial_events(struct disas_state *state, int status)
{
	int errcode, initial;

	initial = 1;
	for (;;) {
		if (!(status & pts_event_pending))
			break;

		status = pt_query_event(state->decoder, &state->event);
		if (status < 0)
			return status;

		errcode = proceed_to_event(state, status);
		if (errcode < 0)
			return errcode;

		/* Switch to normal event processing once we see the first
		 * non-status update event.
		 */
		initial = initial && (status & pts_status_event);

		/* Process initial status update events normally, i.e. without
		 * checking for state inconsistencies.
		 */
		if (initial)
			status &= ~pts_status_event;

		errcode = process_event(state, status);
		if (errcode < 0)
			return errcode;
	}

	return 0;
}

void disas(struct pt_decoder *decoder, struct load_map *elfmap)
{
	struct disas_state state;

	for (;;) {
		enum pt_error_code errcode;
		int status;

		disas_init(&state, decoder, elfmap);

		status = pt_sync_forward(decoder);
		if (!status)
			status = pt_query_start(decoder, &state.ip);

		if (status < 0) {
			errcode = pt_errcode(status);

			/* We're done when we reached the end of the trace. */
			if (errcode == pte_eos)
				return;

			printf("[%" PRIu64 ", 0x%" PRIx64 ": "
			       "sync error (%d): %s]\n",
			       pt_get_decoder_pos(decoder), state.ip, errcode,
			       pt_errstr(errcode));
			break;
		}

		/* A suppressed IP means that PT is disabled.  */
		if (status & pts_ip_suppressed)
			state.flags |= pf_pt_disabled;

		/* Process initial events to initialize our internal state. */
		status = process_initial_events(&state, status);

		/* Proceed until we run into an error. */
		while (status >= 0) {
			/* If we end up being disabled after processing events,
			   try to resync. */
			if (state.flags & pf_pt_disabled)
				break;

			status = proceed(&state);

			if (status >= 0)
				status = process_pending_events(&state, status);
		}

		errcode = pt_errcode(status);
		switch (errcode) {
		case pte_eos:
			/* We're done when we reach the end of the trace. */
			return;

		case pte_ok:
			/* We fell out of the proceed loop without error. */
			break;

		default:
			/* We exited the proceed loop due to an error. */
			printf("[%" PRIu64 ", 0x%" PRIx64 ": "
			       "resyncing due to error (%d): %s]\n",
			       pt_get_decoder_pos(decoder), state.ip, errcode,
			       pt_errstr(errcode));
			break;
		}
	}
}
