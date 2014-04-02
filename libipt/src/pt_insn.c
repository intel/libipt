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

#include "pt_insn_decoder.h"
#include "pt_section.h"

#include "intel-pt.h"

#include <string.h>


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

int pt_insn_sync_forward(struct pt_insn_decoder *decoder)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	errcode = pt_qry_sync_forward(&decoder->query, &decoder->ip);
	if (errcode < 0)
		goto out;

	if (!(errcode & pts_ip_suppressed))
		decoder->enabled = 1;

out:
	decoder->status = errcode;
	if (errcode < 0)
		return errcode;

	return 0;
}

int pt_insn_sync_backward(struct pt_insn_decoder *decoder)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	errcode = pt_qry_sync_backward(&decoder->query, &decoder->ip);

	decoder->status = errcode;
	if (errcode < 0)
		return errcode;

	return 0;
}

int pt_insn_get_offset(struct pt_insn_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_get_offset(&decoder->query, offset);
}

int pt_insn_time(struct pt_insn_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_time(&decoder->query, offset);
}

int pt_insn_add_file(struct pt_insn_decoder *decoder, const char *filename,
		     uint64_t offset, uint64_t size, uint64_t vaddr)
{
	struct pt_section *section;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	section = pt_mk_section(filename, offset, size, vaddr);
	if (!section)
		return -pte_invalid;

	errcode = pt_image_add(&decoder->image, section);
	if (errcode < 0)
		pt_section_free(section);

	return errcode;
}

int pt_insn_remove_by_filename(struct pt_insn_decoder *decoder,
			       const char *filename)
{
	if (!decoder)
		return -pte_invalid;

	return pt_image_remove_by_name(&decoder->image, filename);
}

int pt_insn_add_callback(struct pt_insn_decoder *decoder,
			 read_memory_callback_t *callback, void *context)
{
	if (!decoder)
		return -pte_invalid;

	return pt_image_replace_callback(&decoder->image, callback, context);
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
	pti_ild_t *ild;
	pti_bool_t status, relevant;
	int size;

	if (!insn || !decoder)
		return -pte_internal;

	/* Fill in as much as we can as early as we can so we have the
	 * information available in case of errors.
	 */
	insn->speculative = decoder->speculative;
	insn->mode = decoder->mode;
	insn->ip = decoder->ip;

	/* Read the memory at the current IP. */
	size = pt_image_read(&decoder->image, insn->raw, sizeof(insn->raw),
			     decoder->ip);
	if (size < 0)
		return size;

	/* Decode the instruction. */
	ild = &decoder->ild;
	memset(ild, 0, sizeof(*ild));

	ild->itext = insn->raw;
	ild->max_bytes = size;
	ild->mode = translate_mode(decoder->mode);
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

static int event_pending(struct pt_insn_decoder *decoder)
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

	status = pt_qry_event(&decoder->query, &decoder->event);
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
	insn->enabled = 1;

	/* Clear an indication of a preceding disable on the same
	 * instruction.
	 */
	insn->disabled = 0;

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

static int process_async_branch_event(struct pt_insn_decoder *decoder,
				      struct pt_insn *insn)
{
	struct pt_event *ev;

	if (!decoder || !insn)
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

static int process_paging_event(struct pt_insn_decoder *decoder,
				struct pt_insn *insn)
{
	if (!decoder || !insn)
		return -pte_internal;

	/* We do currently not support paging. */
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

	/* Disable tracing if we don't have an IP. */
	if (ev->ip_suppressed) {
		decoder->enabled = 0;
		return 1;
	}

	decoder->ip = ev->variant.overflow.ip;
	insn->resynced = 1;

	return 1;
}

static int process_exec_mode_event(struct pt_insn_decoder *decoder,
				   struct pt_insn *insn)
{
	enum pt_exec_mode mode;
	struct pt_event *ev;

	if (!decoder || !insn)
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

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;

	decoder->speculative = ev->variant.tsx.speculative;

	if (insn && decoder->enabled) {
		if (ev->variant.tsx.aborted)
			insn->aborted = 1;
		else if (!ev->variant.tsx.speculative)
			insn->committed = 1;
	}

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
			return process_async_branch_event(decoder, insn);

		return 0;

	case ptev_async_disabled:
		/* We would normally process the disabled event when peeking
		 * at the next instruction in order to indicate the disabling
		 * properly.
		 * This is to catch the case where we disable tracing before
		 * we actually started.
		 */
		if (ev->variant.async_disabled.at == decoder->ip)
			return process_disabled_event(decoder, insn);

		return 0;

	case ptev_async_paging:
		if (ev->ip_suppressed ||
		    ev->variant.async_paging.ip == decoder->ip)
			return process_paging_event(decoder, insn);

		return 0;

	case ptev_disabled:
	case ptev_paging:
		return 0;

	case ptev_overflow:
		return process_overflow_event(decoder, insn);

	case ptev_exec_mode:
		if (ev->ip_suppressed ||
		    ev->variant.exec_mode.ip == decoder->ip)
			return process_exec_mode_event(decoder, insn);

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
	case ptev_async_disabled:
	case ptev_async_branch:
	case ptev_exec_mode:
	case ptev_tsx:
		/* We will process those events on the next iteration. */
		return 0;

	case ptev_disabled:
		ild = &decoder->ild;

		if (ev->ip_suppressed) {
			if (ild->u.s.branch ||
			    pt_insn_changes_cpl(ild) ||
			    pt_insn_changes_cr3(ild))
				return process_disabled_event(decoder, insn);

		} else if (ild->u.s.branch) {
			if (!ild->u.s.branch_direct ||
			    ild->u.s.cond ||
			    ild->direct_target == ev->variant.disabled.ip)
				return process_disabled_event(decoder, insn);
		}

		return 0;

	case ptev_paging:
		if (pt_insn_changes_cr3(&decoder->ild))
			return process_paging_event(decoder, insn);

		return 0;
	}

	return -pte_internal;
}

static int process_events_after(struct pt_insn_decoder *decoder,
				struct pt_insn *insn)
{
	if (!decoder || !insn)
		return -pte_internal;

	for (;;) {
		int pending, processed, errcode;

		pending = event_pending(decoder);
		if (pending < 0)
			return pending;

		if (!pending)
			break;

		processed = process_one_event_after(decoder, insn);
		if (processed < 0)
			return processed;

		if (!processed)
			break;

		decoder->process_event = 0;

		errcode = process_events_before(decoder, insn);
		if (errcode < 0)
			return errcode;
	}

	return 0;
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
			return process_disabled_event(decoder, insn);

		return 0;

	case ptev_tsx:
		if (ev->ip_suppressed ||
		    ev->variant.tsx.ip == decoder->ip)
			return process_tsx_event(decoder, insn);

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
		return 0;

	case ptev_exec_mode:
		/* We would normally process this event in the next iteration.
		 *
		 * We process it here, as well, in case we have a peek event
		 * hiding behind.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.exec_mode.ip == decoder->ip)
			return process_exec_mode_event(decoder, insn);

		return 0;

	case ptev_async_paging:
		/* We would normally process this event in the next iteration.
		 *
		 * We process it here, as well, in case we have a peek event
		 * hiding behind.
		 */
		if (ev->ip_suppressed ||
		    ev->variant.async_paging.ip == decoder->ip)
			return process_paging_event(decoder, insn);

		return 0;

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

int pt_insn_next(struct pt_insn_decoder *decoder, struct pt_insn *insn)
{
	int errcode;

	if (!insn || !decoder)
		return -pte_invalid;

	memset(insn, 0, sizeof(*insn));

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

	/* As long as we have not decoded the instruction, it is OK to change
	 * the IP - as would, for example, an enabled event.
	 */
	decoder->event_may_change_ip = 1;

	errcode = process_events_before(decoder, insn);
	if (errcode < 0)
		goto err;

	/* If tracing is disabled at this point, we should be at the end
	 * of the trace - otherwise there should have been a re-enable
	 * event.
	 */
	if (!decoder->enabled) {
		struct pt_event event;

		/* Any query should give us an end of stream, error. */
		errcode = pt_qry_event(&decoder->query, &event);
		if (errcode != -pte_eos)
			errcode = -pte_internal;

		goto err;
	}

	errcode = decode_insn(insn, decoder);
	if (errcode < 0)
		goto err;

	/* After decoding the instruction, we must not change the IP in this
	 * iteration - postpone processing of events that would to the next
	 * iteration.
	 */
	decoder->event_may_change_ip = 0;

	errcode = process_events_after(decoder, insn);
	if (errcode < 0)
		goto err;

	/* If event processing disabled tracing, we're done for this
	 * iteration - we will process the re-enable event on the next.
	 */
	if (!decoder->enabled)
		return 0;

	/* Determine the next IP. */
	errcode = proceed(decoder);
	if (errcode < 0)
		goto err;

	/* Peek event processing is based on the next instruction's IP
	 * and is therefore independent of the relevance of @insn.
	 */
	errcode = process_events_peek(decoder, insn);
	if (errcode < 0)
		goto err;

	return 0;

err:
	decoder->status = errcode;
	return errcode;
}
