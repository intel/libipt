/*
 * Copyright (c) 2013-2015, Intel Corporation
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

#include "intel-pt.h"

#include <string.h>


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

int pt_insn_decoder_init(struct pt_insn_decoder *decoder,
			 const struct pt_config *config)
{
	int errcode;

	if (!decoder)
		return -pte_internal;

	errcode = pt_qry_decoder_init(&decoder->query, config);
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

	decoder->status = status;
	if (status < 0)
		return status;

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

static enum pt_insn_class pt_insn_classify(const pti_ild_t *ild)
{
	if (!ild || ild->u.s.error)
		return ptic_error;

	if (!ild->u.s.branch)
		return ptic_other;

	if (ild->u.s.cond)
		return ptic_cond_jump;

	if (ild->u.s.call)
		return ild->u.s.branch_far ? ptic_far_call : ptic_call;

	if (ild->u.s.ret)
		return ild->u.s.branch_far ? ptic_far_return : ptic_return;

	return ild->u.s.branch_far ? ptic_far_jump : ptic_jump;
}

static int pt_insn_changes_cpl(const pti_ild_t *ild)
{
	if (!ild)
		return 0;

	switch (ild->iclass) {
	default:
		return 0;

	case PTI_INST_INT:
	case PTI_INST_INT3:
	case PTI_INST_INT1:
	case PTI_INST_INTO:
	case PTI_INST_IRET:
	case PTI_INST_SYSCALL:
	case PTI_INST_SYSENTER:
	case PTI_INST_SYSEXIT:
	case PTI_INST_SYSRET:
		return 1;
	}
}

static int pt_insn_changes_cr3(const pti_ild_t *ild)
{
	if (!ild)
		return 0;

	switch (ild->iclass) {
	default:
		return 0;

	case PTI_INST_MOV_CR3:
		return 1;
	}
}

static int pt_insn_is_far_branch(const pti_ild_t *ild)
{
	if (!ild)
		return 0;

	return ild->u.s.branch_far;
}

static int pt_insn_binds_to_pip(const pti_ild_t *ild)
{
	if (!ild)
		return 0;

	switch (ild->iclass) {
	default:
		break;

	case PTI_INST_MOV_CR3:
	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		return 1;
	}

	return pt_insn_is_far_branch(ild);
}

static int pt_insn_binds_to_vmcs(const pti_ild_t *ild)
{
	if (!ild)
		return 0;

	switch (ild->iclass) {
	default:
		break;

	case PTI_INST_VMPTRLD:
	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		return 1;
	}

	return pt_insn_is_far_branch(ild);
}

/* Try to determine the next IP for @ild without using Intel PT.
 *
 * If @ip is not NULL, provides the determined IP on success.
 *
 * Returns 0 on success.
 * Returns a negative error code, otherwise.
 * Returns -pte_bad_query if determining the IP would require Intel PT.
 * Returns -pte_bad_insn if @ild has not been decoded correctly.
 * Returns -pte_invalid if @ild is NULL.
 */
static int pt_insn_next_ip(uint64_t *ip, const pti_ild_t *ild)
{
	if (!ild)
		return -pte_invalid;

	if (ild->u.s.error)
		return -pte_bad_insn;

	if (!ild->u.s.branch) {
		if (ip)
			*ip = ild->runtime_address + ild->length;
		return 0;
	}

	if (ild->u.s.cond)
		return -pte_bad_query;

	if (ild->u.s.branch_direct) {
		if (ip)
			*ip = ild->direct_target;
		return 0;
	}

	return -pte_bad_query;
}

static pti_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return PTI_MODE_LAST;

	case ptem_16bit:
		return PTI_MODE_16;

	case ptem_32bit:
		return PTI_MODE_32;

	case ptem_64bit:
		return PTI_MODE_64;
	}

	return PTI_MODE_LAST;
}

/* Decode and analyze one instruction.
 *
 * Decodes the instructruction at @decoder->ip into @insn and updates
 * @decoder->ip.
 *
 * Returns a negative error code on failure.
 * Returns zero on success if the instruction is not relevant for our purposes.
 * Returns a positive number on success if the instruction is relevant.
 * Returns -pte_bad_insn if the instruction could not be decoded.
 */
static int decode_insn(struct pt_insn *insn, struct pt_insn_decoder *decoder)
{
	static pti_machine_mode_enum_t mode;
	pti_ild_t *ild;
	pti_bool_t status, relevant;
	int size;

	if (!insn || !decoder)
		return -pte_internal;

	/* Fill in as much as we can as early as we can so we have the
	 * information available in case of errors.
	 */
	if (decoder->speculative)
		insn->speculative = 1;
	insn->mode = decoder->mode;
	insn->ip = decoder->ip;

	/* If we don't know the execution mode, we can't decode. */
	mode = translate_mode(decoder->mode);
	if (PTI_MODE_LAST <= mode)
		return -pte_bad_insn;

	/* Read the memory at the current IP in the current address space. */
	size = pt_image_read(decoder->image, insn->raw, sizeof(insn->raw),
			     &decoder->asid, decoder->ip);
	if (size < 0)
		return size;

	/* Decode the instruction. */
	ild = &decoder->ild;
	memset(ild, 0, sizeof(*ild));

	ild->itext = insn->raw;
	ild->max_bytes = size;
	ild->mode = mode;
	ild->runtime_address = decoder->ip;

	status = pti_instruction_length_decode(ild);
	if (!status)
		return -pte_bad_insn;

	insn->size = (uint8_t) ild->length;

	relevant = pti_instruction_decode(ild);
	if (relevant)
		insn->iclass = pt_insn_classify(ild);
	else
		insn->iclass = ptic_other;

	return relevant;
}

/* Check whether @ip is ahead of us.
 *
 * Tries to reach @ip from @decoder->ip in @decoder->mode without Intel PT for
 * at most @steps steps.
 *
 * Does not update @decoder except for its image LRU cache.
 *
 * Returns non-zero if @ip can be reached, zero otherwise.
 */
static int pt_ip_is_ahead(struct pt_insn_decoder *decoder, uint64_t ip,
			  size_t steps)
{
	pti_machine_mode_enum_t mode;
	uint64_t at;

	if (!decoder)
		return 0;

	/* We do not expect execution mode changes. */
	mode = translate_mode(decoder->mode);
	if (PTI_MODE_LAST <= mode)
		return -pte_bad_insn;

	at = decoder->ip;
	while (at != ip) {
		pti_bool_t status;
		pti_ild_t ild;
		uint8_t raw[pt_max_insn_size];
		int size, errcode;

		if (!steps--)
			return 0;

		/* If we can't read the memory for the instruction, we can't
		 * reach it.
		 */
		size = pt_image_read(decoder->image, raw, sizeof(raw),
				     &decoder->asid, at);
		if (size < 0)
			return 0;

		memset(&ild, 0, sizeof(ild));

		ild.itext = raw;
		ild.max_bytes = size;
		ild.mode = mode;
		ild.runtime_address = at;

		status = pti_instruction_length_decode(&ild);
		if (!status)
			return 0;

		(void) pti_instruction_decode(&ild);

		errcode = pt_insn_next_ip(&at, &ild);
		if (errcode < 0)
			return 0;
	}

	return 1;
}

static inline int event_pending(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	if (decoder->process_event)
		return 1;

	status = decoder->status;
	if (status < 0)
		return status;

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

	errcode = process_disabled_event(decoder, insn);
	if (errcode <= 0)
		return errcode;

	decoder->last_disable_ip = decoder->ip;

	return errcode;
}

static int process_sync_disabled_event(struct pt_insn_decoder *decoder,
				       struct pt_insn *insn,
				       const pti_ild_t *ild)
{
	int errcode, iperr;

	errcode = process_disabled_event(decoder, insn);
	if (errcode <= 0)
		return errcode;

	iperr = pt_insn_next_ip(&decoder->last_disable_ip, ild);
	if (iperr < 0) {
		/* For indirect calls, assume that we return to the next
		 * instruction.
		 */
		if (iperr == -pte_bad_query && ild->u.s.call)
			decoder->last_disable_ip =
				ild->runtime_address + ild->length;
		else
			decoder->last_disable_ip = 0ull;
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

	/* Delay processing of the event if we can't change the IP. */
	if (!decoder->event_may_change_ip)
		return 0;

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
		return -pte_nosync;

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
		if (ev->variant.async_disabled.at == decoder->ip)
			return process_async_disabled_event(decoder, insn);

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

	case ptev_vmcs:
	case ptev_disabled:
		return 0;

	case ptev_paging:
		if (!decoder->enabled)
			return process_paging_event(decoder);

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

static int process_one_event_after(struct pt_insn_decoder *decoder,
				   struct pt_insn *insn)
{
	struct pt_event *ev;
	const pti_ild_t *ild;

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
		ild = &decoder->ild;

		if (ev->ip_suppressed) {
			if ((ild->u.s.branch && ild->u.s.branch_far) ||
			    pt_insn_changes_cpl(ild) ||
			    pt_insn_changes_cr3(ild))
				return process_sync_disabled_event(decoder,
								   insn, ild);

		} else if (ild->u.s.branch) {
			if (!ild->u.s.branch_direct ||
			    ild->u.s.cond ||
			    ild->direct_target == ev->variant.disabled.ip)
				return process_sync_disabled_event(decoder,
								   insn, ild);
		}

		return 0;

	case ptev_paging:
		if (pt_insn_binds_to_pip(&decoder->ild) &&
		    !decoder->paging_event_bound) {
			/* Each instruction only binds to one paging event. */
			decoder->paging_event_bound = 1;

			return process_paging_event(decoder);
		}

		return 0;

	case ptev_vmcs:
		if (pt_insn_binds_to_vmcs(&decoder->ild) &&
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
				struct pt_insn *insn)
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
		processed = process_one_event_after(decoder, insn);
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

static int process_one_event_peek(struct pt_insn_decoder *decoder,
				  struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_async_disabled:
		if (ev->variant.async_disabled.at == decoder->ip)
			return process_async_disabled_event(decoder, insn);

		return 0;

	case ptev_tsx:
		if (ev->ip_suppressed ||
		    ev->variant.tsx.ip == decoder->ip)
			return process_tsx_event(decoder, insn);

		/* If we got the TSX event after a bogus branch, we might
		 * be on the wrong track.
		 *
		 * Check if we can reach the TSX event IP from here.  If we
		 * can't, assume that this is due to erratum BDM64.  We
		 * pretend that we're already at the TSX event IP and process
		 * the event.
		 *
		 * If we can reach the TSX event IP from here, we migth still
		 * be wrong, but we won't be able to tell.
		 */
		if (decoder->query.config.errata.bdm64 &&
		    ev->variant.tsx.aborted && decoder->ild.u.s.branch &&
		    !pt_ip_is_ahead(decoder, ev->variant.tsx.ip, 0x1000)) {
			decoder->ip = ev->variant.tsx.ip;
			return process_tsx_event(decoder, insn);
		}

		return 0;

	case ptev_async_branch:
		/* The event is processed on the next iteration.
		 *
		 * We indicate the interrupt in the preceding instruction.
		 */
		if (ev->variant.async_branch.from == decoder->ip)
			insn->interrupted = 1;

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

		processed = process_one_event_peek(decoder, insn);
		if (processed < 0)
			return processed;

		if (!processed)
			break;

		decoder->process_event = 0;
	}

	return 0;
}

static int proceed(struct pt_insn_decoder *decoder)
{
	const pti_ild_t *ild;

	if (!decoder)
		return -pte_internal;

	ild = &decoder->ild;

	if (ild->u.s.error)
		return -pte_bad_insn;

	if (!ild->u.s.branch) {
		decoder->ip += ild->length;
		return 0;
	}

	if (ild->u.s.cond) {
		int status, taken;

		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status < 0)
			return status;

		decoder->status = status;
		if (!taken) {
			decoder->ip += ild->length;
			return 0;
		}

		/* Fall through to process the taken branch. */
	} else if (ild->u.s.call && !ild->u.s.branch_far) {
		/* Log the call for return compression. */
		pt_retstack_push(&decoder->retstack, decoder->ip + ild->length);

		/* Fall through to process the call. */
	} else if (ild->u.s.ret && !ild->u.s.branch_far) {
		int taken, status;

		/* Check for a compressed return. */
		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status >= 0) {
			int errcode;

			decoder->status = status;

			/* A compressed return is indicated by a taken
			 * conditional branch.
			 */
			if (!taken)
				return -pte_nosync;

			errcode = pt_retstack_pop(&decoder->retstack,
						  &decoder->ip);
			if (errcode < 0)
				return errcode;

			return 0;
		}

		/* Fall through to process the uncompressed return. */
	}

	/* Process the actual branch. */
	if (ild->u.s.branch_direct)
		decoder->ip = ild->direct_target;
	else {
		int status;

		status = pt_qry_indirect_branch(&decoder->query,
						&decoder->ip);

		if (status < 0)
			return status;

		/* We do need an IP to proceed. */
		if (status & pts_ip_suppressed)
			return -pte_noip;

		decoder->status = status;
	}

	return 0;
}

static int pt_insn_peek(struct pt_insn_decoder *decoder, struct pt_insn *insn)
{
	int errcode;

	/* Determine the next IP. */
	errcode = proceed(decoder);
	if (errcode < 0)
		return errcode;

	/* Peek event processing is based on the next instruction's
	 * IP and is therefore independent of the relevance of @insn.
	 */
	errcode = process_events_peek(decoder, insn);
	if (errcode < 0)
		return errcode;

	return 0;
}

static int pt_insn_status(const struct pt_insn_decoder *decoder)
{
	int status, flags;

	if (!decoder)
		return -pte_internal;

	status = decoder->status;
	flags = 0;

	/* We postpone any errors until the next query. */
	if (status < 0)
		return 0;

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
	struct pt_insn insn, *pinsn;
	int errcode, status;

	if (!uinsn || !decoder)
		return -pte_invalid;

	pinsn = size == sizeof(insn) ? uinsn : &insn;

	/* Zero-initialize the instruction in case of error returns. */
	memset(pinsn, 0, sizeof(*pinsn));

	/* Report any errors we encountered. */
	if (decoder->status < 0)
		return decoder->status;

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
			errcode = -pte_bad_context;

		goto err;
	}

	errcode = decode_insn(pinsn, decoder);
	if (errcode < 0)
		goto err;

	/* After decoding the instruction, we must not change the IP in this
	 * iteration - postpone processing of events that would to the next
	 * iteration.
	 */
	decoder->event_may_change_ip = 0;

	errcode = process_events_after(decoder, pinsn);
	if (errcode < 0)
		goto err;

	/* We return the decoder status for this instruction. */
	status = pt_insn_status(decoder);

	/* If event processing disabled tracing, we're done for this
	 * iteration - we will process the re-enable event on the next.
	 *
	 * Otherwise, we determine the next instruction and peek ahead.
	 *
	 * This may indicate an event already in this instruction.  Any error
	 * will be logged for the next iteration.
	 */
	if (decoder->enabled) {
		errcode = pt_insn_peek(decoder, pinsn);
		if (errcode < 0)
			decoder->status = errcode;
	}

	errcode = insn_to_user(uinsn, size, pinsn);
	if (errcode < 0)
		goto err_log;

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

err_log:
	decoder->status = errcode;
	return errcode;
}
