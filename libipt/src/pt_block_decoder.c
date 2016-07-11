/*
 * Copyright (c) 2016, Intel Corporation
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

#include "pt_block_decoder.h"
#include "pt_insn.h"
#include "pt_ild.h"

#include "intel-pt.h"

#include <string.h>


static int pt_blk_proceed(struct pt_block_decoder *, struct pt_block *);
static int pt_blk_process_trailing_events(struct pt_block_decoder *,
					  struct pt_block *);


static void pt_blk_reset(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	decoder->mode = ptem_unknown;
	decoder->ip = 0ull;
	decoder->status = 0;
	decoder->enabled = 0;
	decoder->process_event = 0;
	decoder->speculative = 0;

	pt_retstack_init(&decoder->retstack);
	pt_asid_init(&decoder->asid);
}

int pt_blk_decoder_init(struct pt_block_decoder *decoder,
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

	pt_blk_reset(decoder);

	return 0;
}

void pt_blk_decoder_fini(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	pt_image_fini(&decoder->default_image);
	pt_qry_decoder_fini(&decoder->query);
}

struct pt_block_decoder *
pt_blk_alloc_decoder(const struct pt_config *config)
{
	struct pt_block_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_blk_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_blk_free_decoder(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	pt_blk_decoder_fini(decoder);
	free(decoder);
}

static int pt_blk_start(struct pt_block_decoder *decoder, int status)
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

static int pt_blk_sync_reset(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	pt_blk_reset(decoder);

	return 0;
}

int pt_blk_sync_forward(struct pt_block_decoder *decoder)
{
	int errcode, status;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_blk_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	status = pt_qry_sync_forward(&decoder->query, &decoder->ip);

	return pt_blk_start(decoder, status);
}

int pt_blk_sync_backward(struct pt_block_decoder *decoder)
{
	int errcode, status;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_blk_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	status = pt_qry_sync_backward(&decoder->query, &decoder->ip);

	return pt_blk_start(decoder, status);
}

int pt_blk_sync_set(struct pt_block_decoder *decoder, uint64_t offset)
{
	int errcode, status;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_blk_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	status = pt_qry_sync_set(&decoder->query, &decoder->ip, offset);

	return pt_blk_start(decoder, status);
}

int pt_blk_get_offset(struct pt_block_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_get_offset(&decoder->query, offset);
}

int pt_blk_get_sync_offset(struct pt_block_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_qry_get_sync_offset(&decoder->query, offset);
}

struct pt_image *pt_blk_get_image(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return decoder->image;
}

int pt_blk_set_image(struct pt_block_decoder *decoder, struct pt_image *image)
{
	if (!decoder)
		return -pte_invalid;

	if (!image)
		image = &decoder->default_image;

	decoder->image = image;
	return 0;
}

const struct pt_config *
pt_blk_get_config(const struct pt_block_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_qry_get_config(&decoder->query);
}

int pt_blk_time(struct pt_block_decoder *decoder, uint64_t *time,
		uint32_t *lost_mtc, uint32_t *lost_cyc)
{
	if (!decoder || !time)
		return -pte_invalid;

	return pt_qry_time(&decoder->query, time, lost_mtc, lost_cyc);
}

int pt_blk_core_bus_ratio(struct pt_block_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	return pt_qry_core_bus_ratio(&decoder->query, cbr);
}

/* Fetch the next pending event.
 *
 * Checks for pending events.  If an event is pending, fetches it (if not
 * already in process).
 *
 * Returns zero if no event is pending.
 * Returns a positive integer if an event is pending or in process.
 * Returns a negative error code otherwise.
 */
static inline int pt_blk_fetch_event(struct pt_block_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_internal;

	if (decoder->process_event)
		return 1;

	if (!(decoder->status & pts_event_pending))
		return 0;

	status = pt_qry_event(&decoder->query, &decoder->event,
			      sizeof(decoder->event));
	if (status < 0)
		return status;

	decoder->process_event = 1;
	decoder->status = status;

	return 1;
}

static inline int pt_blk_block_is_empty(const struct pt_block *block)
{
	if (!block)
		return 1;

	return !block->ninsn;
}

static inline int block_to_user(struct pt_block *ublock, size_t size,
				const struct pt_block *block)
{
	if (!ublock || !block)
		return -pte_internal;

	if (ublock == block)
		return 0;

	/* Zero out any unknown bytes. */
	if (sizeof(*block) < size) {
		memset(ublock + sizeof(*block), 0, size - sizeof(*block));

		size = sizeof(*block);
	}

	memcpy(ublock, block, size);

	return 0;
}

static int pt_insn_false(const struct pt_insn *insn,
			 const struct pt_insn_ext *iext)
{
	(void) insn;
	(void) iext;

	return 0;
}

/* Determine the next IP using trace.
 *
 * Tries to determine the IP of the next instruction using trace and provides it
 * in @pip.
 *
 * Not requiring trace to determine the IP is treated as an internal error.
 *
 * Does not update the return compression stack for indirect calls.  This is
 * expected to have been done, already, when trying to determine the next IP
 * without using trace.
 *
 * Does not update @decoder->status.  The caller is expected to do that.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 * Returns -pte_internal if @pip, @decoder, @insn, or @iext are NULL.
 * Returns -pte_internal if no trace is required.
 */
static int pt_blk_next_ip(uint64_t *pip, struct pt_block_decoder *decoder,
			  const struct pt_insn *insn,
			  const struct pt_insn_ext *iext)
{
	int status;

	if (!pip || !decoder || !insn || !iext)
		return -pte_internal;

	/* We handle non-taken conditional branches, and compressed returns
	 * directly in the switch.
	 *
	 * All kinds of branches are handled below the switch.
	 */
	switch (insn->iclass) {
	case ptic_cond_jump: {
		uint64_t ip;
		int taken;

		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status < 0)
			return status;

		ip = insn->ip + insn->size;
		if (taken)
			ip += iext->variant.branch.displacement;

		*pip = ip;
		return status;
	}

	case ptic_return: {
		int taken, errcode;

		/* Check for a compressed return. */
		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status < 0) {
			if (status != -pte_bad_query)
				return status;

			break;
		}

		/* A compressed return is indicated by a taken conditional
		 * branch.
		 */
		if (!taken)
			return -pte_bad_retcomp;

		errcode = pt_retstack_pop(&decoder->retstack, pip);
		if (errcode < 0)
			return errcode;

		return status;
	}

	case ptic_jump:
	case ptic_call:
		/* A direct jump or call wouldn't require trace. */
		if (iext->variant.branch.is_direct)
			return -pte_internal;

		break;

	case ptic_far_call:
	case ptic_far_return:
	case ptic_far_jump:
		break;

	case ptic_other:
		return -pte_internal;

	case ptic_error:
		return -pte_bad_insn;
	}

	/* Process an indirect branch.
	 *
	 * This covers indirect jumps and calls, non-compressed returns, and all
	 * flavors of far transfers.
	 */
	return pt_qry_indirect_branch(&decoder->query, pip);
}

/* Process an enabled event.
 *
 * Determines whether the enabled event can be processed in this iteration or
 * has to be postponed.
 *
 * If the event can be processed, do so and proceed.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_enabled(struct pt_block_decoder *decoder,
				  struct pt_block *block,
				  const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must have an IP in order to start decoding. */
	if (ev->ip_suppressed)
		return -pte_noip;

	/* We must currently be disabled. */
	if (decoder->enabled)
		return -pte_bad_context;

	/* Delay processing of the event if the block is alredy in progress. */
	if (!pt_blk_block_is_empty(block))
		return 0;

	/* Check if we resumed from a preceding disable or if we enabled at a
	 * different position.
	 */
	if (ev->variant.enabled.ip == decoder->ip && !block->enabled)
		block->resumed = 1;
	else {
		block->enabled = 1;
		block->resumed = 0;
	}

	/* Clear an indication of a preceding disable. */
	block->disabled = 0;

	block->ip = decoder->ip = ev->variant.enabled.ip;
	decoder->enabled = 1;
	decoder->process_event = 0;

	return pt_blk_proceed(decoder, block);
}

/* Apply a disabled event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_disabled(struct pt_block_decoder *decoder,
				 struct pt_block *block,
				 const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	/* We preserve @decoder->ip.  This is where we expect tracing to resume
	 * and we'll indicate that on the subsequent enabled event if tracing
	 * actually does resume from there.
	 */
	decoder->enabled = 0;
	decoder->process_event = 0;

	block->disabled = 1;

	return 0;
}

/* Process a disabled event.
 *
 * We reached the location of a disabled event.  This ends a non-empty block.
 *
 * We may see disabled events for empty blocks when we have a series of enables
 * and disabled on the same IP without any trace in between.  We ignore the
 * disabled event in this case and proceed.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_disabled(struct pt_block_decoder *decoder,
				   struct pt_block *block,
				   const struct pt_event *ev)
{
	int errcode;

	if (!block)
		return -pte_internal;

	errcode = pt_blk_apply_disabled(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	/* The event completes a non-empty block. */
	if (!pt_blk_block_is_empty(block))
		return 0;

	/* Ignore the disable if the block is empty. */
	block->disabled = 0;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing disabled event.
 *
 * We reached the location of a disabled event after completing a block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_disabled(struct pt_block_decoder *decoder,
					    struct pt_block *block,
					    const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_disabled(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Apply an asynchronous branch event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_async_branch(struct pt_block_decoder *decoder,
				     struct pt_block *block,
				     const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	/* Indicate the async branch as an interrupt.  This ends the block. */
	block->interrupted = 1;

	/* Jump to the branch destination.  We will continue from there in the
	 * next iteration.
	 */
	decoder->ip = ev->variant.async_branch.to;
	decoder->process_event = 0;

	return 0;
}

/* Process an asynchronous branch event.
 *
 * We reached the source location of an asynchronous branch.  This ends a
 * non-empty block.
 *
 * We may come across an asynchronous branch for an empty block, e.g. when
 * tracing just started.  We ignore the event in that case and proceed.  It will
 * look like tracing started at the asynchronous branch destination instead of
 * at its source.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_async_branch(struct pt_block_decoder *decoder,
				       struct pt_block *block,
				       const struct pt_event *ev)
{
	int errcode;

	if (!block)
		return -pte_internal;

	errcode = pt_blk_apply_async_branch(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	if (!pt_blk_block_is_empty(block))
		return 0;

	/* We may still change the start IP for an empty block.  Do not indicate
	 * the interrupt in this case.
	 */
	block->interrupted = 0;
	block->ip = decoder->ip;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing asynchronous branch event.
 *
 * We reached the source location of an asynchronous branch after completing a
 * block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int
pt_blk_process_trailing_async_branch(struct pt_block_decoder *decoder,
				     struct pt_block *block,
				     const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_async_branch(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Apply a paging event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_paging(struct pt_block_decoder *decoder,
			       struct pt_block *block,
			       const struct pt_event *ev)
{
	(void) block;

	if (!decoder || !ev)
		return -pte_internal;

	decoder->asid.cr3 = ev->variant.paging.cr3;
	decoder->process_event = 0;

	return 0;
}

/* Process a paging event.
 *
 * We reached the location of a paging event.  Update CR3 and proceed.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_paging(struct pt_block_decoder *decoder,
				 struct pt_block *block,
				 const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_paging(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing paging event.
 *
 * We reached the location of a paging event after completing a block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_paging(struct pt_block_decoder *decoder,
					  struct pt_block *block,
					  const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_paging(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Apply a vmcs event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_vmcs(struct pt_block_decoder *decoder,
			     struct pt_block *block,
			     const struct pt_event *ev)
{
	(void) block;

	if (!decoder || !ev)
		return -pte_internal;

	decoder->asid.vmcs = ev->variant.vmcs.base;
	decoder->process_event = 0;

	return 0;
}

/* Process a vmcs event.
 *
 * We reached the location of a vmcs event.  Update VMCS base and proceed.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_vmcs(struct pt_block_decoder *decoder,
			       struct pt_block *block,
			       const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_vmcs(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing vmcs event.
 *
 * We reached the location of a vmcs event after completing a block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_vmcs(struct pt_block_decoder *decoder,
					struct pt_block *block,
					const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_vmcs(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Process an overflow event.
 *
 * An overflow ends a non-empty block.  The overflow itself is indicated in the
 * next block.  Indicate the overflow and resume in this case.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_overflow(struct pt_block_decoder *decoder,
				   struct pt_block *block,
				   const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* The overflow ends a non-empty block.  We will process the event in
	 * the next iteration.
	 */
	if (!pt_blk_block_is_empty(block))
		return 0;

	/* If the IP is suppressed, the overflow resolved while tracing was
	 * disabled.  Otherwise it resolved while tracing was enabled.
	 */
	if (ev->ip_suppressed) {
		/* Tracing is disabled.  It doesn't make sense to preserve the
		 * previous IP.  This will just be misleading.  Even if tracing
		 * had been disabled before, as well, we might have missed the
		 * re-enable in the overflow.
		 */
		decoder->enabled = 0;
		decoder->ip = 0ull;

		/* Indicate the overflow.  Since tracing is disabled, the block
		 * will remain empty until tracing gets re-enabled again.
		 *
		 * When the block is eventually returned it will have the resync
		 * and the enabled bit set to indicate the the overflow resolved
		 * before tracing was enabled.
		 */
		block->resynced = 1;
	} else {
		/* Tracing is enabled and we're at the IP at which the overflow
		 * resolved.
		 */
		decoder->enabled = 1;
		decoder->ip = ev->variant.overflow.ip;

		/* Indicate the overflow and set the start IP.  The block is
		 * empty so we may still change it.
		 *
		 * We do not indicate a tracing enable if tracing had been
		 * disabled before to distinguish this from the above case.
		 */
		block->resynced = 1;
		block->ip = decoder->ip;
	}

	/* We don't know the TSX state.  Let's assume we execute normally.
	 *
	 * We also don't know the execution mode.  Let's keep what we have
	 * in case we don't get an update before we have to decode the next
	 * instruction.
	 */
	decoder->speculative = 0;
	decoder->process_event = 0;

	return pt_blk_proceed(decoder, block);
}

/* Apply an exec mode event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_exec_mode(struct pt_block_decoder *decoder,
				  struct pt_block *block,
				  const struct pt_event *ev)
{
	enum pt_exec_mode mode;

	if (!decoder || !block || !ev)
		return -pte_internal;

	/* Use status update events to diagnose inconsistencies. */
	mode = ev->variant.exec_mode.mode;
	if (ev->status_update && decoder->enabled &&
	    decoder->mode != ptem_unknown && decoder->mode != mode)
		return -pte_bad_status_update;

	decoder->mode = mode;
	decoder->process_event = 0;

	return 0;
}

/* Process an exec mode event.
 *
 * We reached the location of an exec mode event.  Update the exec mode and
 * proceed.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_exec_mode(struct pt_block_decoder *decoder,
				    struct pt_block *block,
				    const struct pt_event *ev)
{
	int errcode;

	if (!decoder || !block)
		return -pte_internal;

	errcode = pt_blk_apply_exec_mode(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	/* An execution mode change ends a non-empty block. */
	if (!pt_blk_block_is_empty(block))
		return 0;

	/* We may still change the execution mode of an empty block. */
	block->mode = decoder->mode;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing exec mode event.
 *
 * We reached the location of an exec mode event after completing a block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_exec_mode(struct pt_block_decoder *decoder,
					     struct pt_block *block,
					     const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_exec_mode(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Apply a tsx event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_tsx(struct pt_block_decoder *decoder,
			    struct pt_block *block,
			    const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	decoder->speculative = ev->variant.tsx.speculative;
	decoder->process_event = 0;

	if (decoder->enabled && !pt_blk_block_is_empty(block)) {
		if (ev->variant.tsx.aborted)
			block->aborted = 1;
		else if (block->speculative && !ev->variant.tsx.speculative)
			block->committed = 1;
	}

	return 0;
}

/* Process a tsx event.
 *
 * We reached the location of a tsx event.  A speculation mode change ends a
 * non-empty block.  Indicate commit or abort in the ended block.
 *
 * We might see tsx event while tracing is disabled or for empty blocks, e.g. if
 * tracing was just enabled.  In this case we do not indicate the abort or
 * commit.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_tsx(struct pt_block_decoder *decoder,
			      struct pt_block *block,
			      const struct pt_event *ev)
{
	int errcode;

	if (!decoder || !block)
		return -pte_internal;

	errcode = pt_blk_apply_tsx(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	/* A speculation mode change ends a non-empty block. */
	if (!pt_blk_block_is_empty(block))
		return 0;

	/* We may still change the speculation mode of an empty block. */
	block->speculative = decoder->speculative;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing tsx event.
 *
 * We reached the location of a tsx event after completing a block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_tsx(struct pt_block_decoder *decoder,
				       struct pt_block *block,
				       const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_tsx(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Apply a stop event.
 *
 * This is used for proceed events and for trailing events.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_apply_stop(struct pt_block_decoder *decoder,
			     struct pt_block *block,
			     const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* Tracing is always disabled before it is stopped. */
	if (decoder->enabled)
		return -pte_bad_context;

	decoder->process_event = 0;

	/* Indicate the stop. */
	block->stopped = 1;

	return 0;
}

/* Process a stop event.
 *
 * We got a stop event.  This always succeeds a disabled event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_stop(struct pt_block_decoder *decoder,
			       struct pt_block *block,
			       const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_stop(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_proceed(decoder, block);
}

/* Process a trailing stop event.
 *
 * We got a stop event.  This always succeeds a disabled event.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_stop(struct pt_block_decoder *decoder,
					struct pt_block *block,
					const struct pt_event *ev)
{
	int errcode;

	errcode = pt_blk_apply_stop(decoder, block, ev);
	if (errcode < 0)
		return errcode;

	return pt_blk_process_trailing_events(decoder, block);
}

/* Check if we can reach a particular IP from the current location.
 *
 * Try to proceed to @ip without using trace.  Do not update any internal state
 * on our way and ignore errors.
 *
 * Returns non-zero if @ip was reached.
 * Returns zero if @ip could not be reached.
 */
static int pt_blk_ip_is_reachable(struct pt_block_decoder *decoder, uint64_t ip,
				  size_t steps)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;

	if (!decoder)
		return 0;

	memset(&insn, 0, sizeof(insn));
	memset(&iext, 0, sizeof(iext));

	/* We do not expect execution mode changes. */
	insn.mode = decoder->mode;
	insn.ip = decoder->ip;

	for (; steps && (insn.ip != ip); --steps) {
		int size, errcode;

		/* If we can't read the memory for the instruction, we can't
		 * reach it.
		 */
		size = pt_image_read(decoder->image, &insn.isid, insn.raw,
				     sizeof(insn.raw), &decoder->asid, insn.ip);
		if (size < 0)
			return 0;

		/* We initialize @insn.size to the maximal possible size.  It
		 * will be set to the actual size during instruction decode.
		 */
		insn.size = (uint8_t) size;

		errcode = pt_ild_decode(&insn, &iext);
		if (errcode < 0)
			return 0;

		errcode = pt_insn_next_ip(&insn.ip, &insn, &iext);
		if (errcode < 0)
			return 0;
	}

	return 1;
}

/* Proceed to the next IP using trace.
 *
 * We failed to proceed without trace.  This ends the current block.  Now use
 * trace to do one final step to determine the start IP of the next block.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_with_trace(struct pt_block_decoder *decoder,
				     const struct pt_insn *insn,
				     const struct pt_insn_ext *iext)
{
	int status;

	if (!decoder)
		return -pte_internal;

	status = pt_blk_next_ip(&decoder->ip, decoder, insn, iext);
	if (status < 0)
		return status;

	/* Preserve the query decoder's response which indicates upcoming
	 * events.
	 */
	decoder->status = status;

	/* We do need an IP in order to proceed. */
	if (status & pts_ip_suppressed)
		return -pte_noip;

	return 0;
}

/* Proceed by one instruction.
 *
 * Tries to decode the instruction at @decoder->ip and, on success, adds it to
 * @block and provides it in @pinsn and @piext.
 *
 * The instruction will not be added if:
 *
 *   - the memory could not be read:  return error
 *   - it could not be decoded:       return error
 *   - @block is already full:        return zero
 *   - @block would switch sections:  return zero
 *
 * Returns a positive integer if the instruction was added.
 * Returns zero if the instruction didn't fit into @block.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_one_insn(struct pt_block_decoder *decoder,
				   struct pt_block *block,
				   struct pt_insn *pinsn,
				   struct pt_insn_ext *piext)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	uint16_t ninsn;
	int status;

	if (!decoder || !block || !pinsn || !piext)
		return -pte_internal;

	/* There's nothing to do if there is no room in @block. */
	ninsn = block->ninsn + 1;
	if (!ninsn)
		return 0;

	insn.mode = decoder->mode;
	insn.ip = decoder->ip;

	status = pt_image_read(decoder->image, &insn.isid, insn.raw,
			       sizeof(insn.raw), &decoder->asid, insn.ip);
	if (status < 0)
		return status;

	/* We do not switch sections inside a block. */
	if (insn.isid != block->isid) {
		if (!pt_blk_block_is_empty(block))
			return 0;

		block->isid = insn.isid;
	}

	insn.size = (uint8_t) status;

	status = pt_ild_decode(&insn, &iext);
	if (status < 0)
		return status;

	/* Log calls' return addresses for return compression.
	 *
	 * Unless this is a call to the next instruction as is used for position
	 * independent code.
	 */
	if ((insn.iclass == ptic_call) &&
	    (!iext.variant.branch.is_direct ||
	     iext.variant.branch.displacement)) {
		status = pt_retstack_push(&decoder->retstack,
					  insn.ip + insn.size);
		if (status < 0)
			return status;
	}

	/* We have a new instruction. */
	block->end_ip = insn.ip;
	block->ninsn = ninsn;

	*pinsn = insn;
	*piext = iext;

	return 1;
}


/* Proceed to a particular type of instruction without using trace.
 *
 * Proceed until we reach an instruction for which @predicate returns a positive
 * integer or until:
 *
 *   - @predicate returns an error:  return error
 *   - @block is full:               return zero
 *   - @block would switch sections: return zero
 *   - we would need trace:          return -pte_bad_query
 *
 * Provide the last instruction that was reached in @insn and @iext.
 *
 * Update @decoder->ip to point to the last IP that was reached.  If we fail due
 * to lack of trace or if we reach a desired instruction, this is @insn->ip;
 * otherwise this is the next instruction's IP.
 *
 * Returns a positive integer if a suitable instruction was reached.
 * Returns zero if no such instruction was reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_insn(struct pt_block_decoder *decoder,
				  struct pt_block *block,
				  struct pt_insn *insn,
				  struct pt_insn_ext *iext,
				  int (*predicate)(const struct pt_insn *,
						   const struct pt_insn_ext *))
{
	int status;

	if (!decoder || !predicate)
		return -pte_internal;

	for (;;) {
		status = pt_blk_proceed_one_insn(decoder, block, insn, iext);
		if (status <= 0)
			return status;

		/* We're done if this instruction matches the spec (positive
		 * status) or we run into an error (negative status).
		 */
		status = predicate(insn, iext);
		if (status != 0)
			return status;

		/* Let's see if we can proceed to the next IP without trace. */
		status = pt_insn_next_ip(&decoder->ip, insn, iext);
		if (status < 0)
			return status;
	}
}

/* Proceed to a particular IP without using trace.
 *
 * Proceed until we reach @ip or until:
 *
 *   - @block is full:               return zero
 *   - @block would switch sections: return zero
 *   - we would need trace:          return -pte_bad_query
 *
 * Provide the last instruction that was reached in @insn and @iext.  If we
 * reached @ip, this is the instruction preceding it.
 *
 * Update @decoder->ip to point to the last IP that was reached.  If we fail due
 * to lack of trace, this is @insn->ip; otherwise this is the next instruction's
 * IP.
 *
 * Returns a positive integer if @ip was reached.
 * Returns zero if no such instruction was reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_ip(struct pt_block_decoder *decoder,
				struct pt_block *block, struct pt_insn *insn,
				struct pt_insn_ext *iext, uint64_t ip)
{
	int status;

	if (!decoder)
		return -pte_internal;

	for (;;) {
		/* We're done when we reach @ip.  We may not even have to decode
		 * a single instruction in some cases.
		 */
		if (decoder->ip == ip)
			return 1;

		status = pt_blk_proceed_one_insn(decoder, block, insn, iext);
		if (status <= 0)
			return status;

		/* Let's see if we can proceed to the next IP without trace. */
		status = pt_insn_next_ip(&decoder->ip, insn, iext);
		if (status < 0)
			return status;
	}
}

/* Proceed to the event location for a disabled event.
 *
 * We have a (synchronous) disabled event pending.  Proceed to the event
 * location and indicate whether we were able to reach it.
 *
 * The last instruction that was reached is stored in @insn/@iext.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_disabled(struct pt_block_decoder *decoder,
				      struct pt_block *block,
				      struct pt_insn *insn,
				      struct pt_insn_ext *iext,
				      const struct pt_event *ev)
{
	if (!decoder || !block || !ev)
		return -pte_internal;


	if (ev->ip_suppressed) {
		/* A synchronous disabled event also binds to far branches and
		 * CPL-changing instructions.  Both would require trace,
		 * however, and are thus implicitly handled by erroring out.
		 *
		 * The would-require-trace error is handled by our caller.
		 */
		return pt_blk_proceed_to_insn(decoder, block, insn, iext,
					      pt_insn_changes_cr3);
	} else
		return pt_blk_proceed_to_ip(decoder, block, insn, iext,
					    ev->variant.disabled.ip);
}

/* Proceed from an instruction at which we stopped previously.
 *
 * We proceeded to @insn/@iext and stopped after decoding and accounting for the
 * instruction but before determining the next IP.
 *
 * Determine the next IP then proceed normally.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_from_insn(struct pt_block_decoder *decoder,
				    struct pt_block *block,
				    const struct pt_insn *insn,
				    const struct pt_insn_ext *iext)
{
	int status;

	if (!decoder)
		return -pte_internal;

	/* Let's see if we can proceed to the next IP without trace. */
	status = pt_insn_next_ip(&decoder->ip, insn, iext);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		return pt_blk_proceed_with_trace(decoder, insn, iext);
	}

	return pt_blk_proceed(decoder, block);
}

/* Try to work around erratum SKD022.
 *
 * If we get an asynchronous disable on VMLAUNCH or VMRESUME, the FUP that
 * caused the disable to be asynchronous might have been bogous.
 *
 * Returns a positive integer if the erratum has been handled.
 * Returns zero if the erratum does not apply.
 * Returns a negative error code otherwise.
 */
static int pt_blk_handle_erratum_skd022(struct pt_block_decoder *decoder,
					struct pt_event *ev)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int size, errcode;

	if (!decoder || !ev)
		return -pte_internal;

	insn.mode = decoder->mode;
	insn.ip = ev->variant.async_disabled.at;

	size = pt_image_read(decoder->image, &insn.isid, insn.raw,
			     sizeof(insn.raw), &decoder->asid, insn.ip);
	if (size < 0)
		return 0;

	/* We initialize @insn.size to the maximal possible size.  It will be
	 * set to the actual size during instruction decode.
	 */
	insn.size = (uint8_t) size;

	errcode = pt_ild_decode(&insn, &iext);
	if (errcode < 0)
		return 0;

	switch (iext.iclass) {
	default:
		/* The erratum does not apply. */
		return 0;

	case PTI_INST_VMLAUNCH:
	case PTI_INST_VMRESUME:
		/* The erratum may apply.  We can't be sure without a lot more
		 * analysis.  Let's assume it does.
		 *
		 * We turn the async disable into a sync disable.  Our caller
		 * will restart event processing.
		 */
		ev->type = ptev_disabled;
		ev->variant.disabled.ip = ev->variant.async_disabled.ip;

		return 1;
	}
}

/* Proceed to the next event.
 *
 * We have an event pending.  Proceed to the event location and either process
 * the event and continue or postpone the event to the next block.
 *
 * On our way to the event location we may also be forced to postpone the event
 * to the next block, e.g. if we overflow the number of instructions in the
 * block or if we need trace in order to reach the event location.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_event(struct pt_block_decoder *decoder,
				struct pt_block *block)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	struct pt_event *ev;
	uint64_t ip;
	int status;

	if (!decoder || !block)
		return -pte_internal;

	if (!decoder->process_event)
		return -pte_internal;

	status = 0;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_enabled:
		return pt_blk_process_enabled(decoder, block, ev);

	case ptev_disabled:
		status = pt_blk_proceed_to_disabled(decoder, block, &insn,
						    &iext, ev);
		if (status <= 0) {
			/* A synchronous disable event also binds to the next
			 * indirect or conditional branch, i.e. to any branch
			 * that would have required trace.
			 */
			if (status != -pte_bad_query)
				break;

			/* The @decoder->ip still points to the indirect or
			 * conditional branch instruction that caused us to
			 * error out.  That's not where we expect tracing to
			 * resume since the instruction already retired.
			 *
			 * For calls, a fair assumption is that tracing resumes
			 * after returning from the called function.  For other
			 * types of instructions, we simply don't know.
			 */
			switch (insn.iclass) {
			case ptic_call:
			case ptic_far_call:
				decoder->ip = insn.ip + insn.size;
				break;

			default:
				decoder->ip = 0ull;
				break;
			}
		}

		return pt_blk_process_disabled(decoder, block, ev);

	case ptev_async_disabled:
		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_disabled.at);
		if (status <= 0)
			break;

		if (decoder->query.config.errata.skd022) {
			status = pt_blk_handle_erratum_skd022(decoder, ev);
			if (status != 0) {
				if (status < 0)
					break;

				return pt_blk_proceed_event(decoder, block);
			}
		}

		return pt_blk_process_disabled(decoder, block, ev);

	case ptev_async_branch:
		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_branch.from);
		if (status <= 0)
			break;

		return pt_blk_process_async_branch(decoder, block, ev);

	case ptev_paging:
		if (!decoder->enabled)
			return pt_blk_process_paging(decoder, block, ev);

		status = pt_blk_proceed_to_insn(decoder, block, &insn, &iext,
						pt_insn_binds_to_pip);
		if (status <= 0)
			break;

		status = pt_blk_apply_paging(decoder, block, ev);
		if (status < 0)
			break;

		return pt_blk_proceed_from_insn(decoder, block, &insn, &iext);

	case ptev_async_paging:
		if (!ev->ip_suppressed) {
			ip = ev->variant.async_paging.ip;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				break;
		}

		return pt_blk_process_paging(decoder, block, ev);

	case ptev_vmcs:
		if (!decoder->enabled)
			return pt_blk_process_vmcs(decoder, block, ev);

		status = pt_blk_proceed_to_insn(decoder, block, &insn, &iext,
						pt_insn_binds_to_vmcs);
		if (status <= 0)
			break;

		status = pt_blk_apply_vmcs(decoder, block, ev);
		if (status < 0)
			break;

		return pt_blk_proceed_from_insn(decoder, block, &insn, &iext);

	case ptev_async_vmcs:
		if (!ev->ip_suppressed) {
			ip = ev->variant.async_vmcs.ip;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				break;
		}

		return pt_blk_process_vmcs(decoder, block, ev);

	case ptev_overflow:
		return pt_blk_process_overflow(decoder, block, ev);

	case ptev_exec_mode:
		if (!ev->ip_suppressed) {
			ip = ev->variant.exec_mode.ip;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				break;
		}

		return pt_blk_process_exec_mode(decoder, block, ev);

	case ptev_tsx:
		if (!ev->ip_suppressed) {
			ip = ev->variant.tsx.ip;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				break;
		}

		return pt_blk_process_tsx(decoder, block, ev);

	case ptev_stop:
		return pt_blk_process_stop(decoder, block, ev);
	}

	return status;
}

/* Proceed to the next decision point.
 *
 * Tracing is enabled and we don't have an event pending.  Proceed as far as
 * we get without trace.  Stop when we either:
 *
 *   - need trace in order to continue
 *   - overflow the max number of instructions in a block
 *
 * We actually proceed one instruction further to get the start IP for the next
 * block.  This only updates @decoder's internal state, though.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_no_event(struct pt_block_decoder *decoder,
				   struct pt_block *block)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int status;

	if (!decoder || !block)
		return -pte_internal;

	/* This is overly conservative, really.  We shouldn't get a bad-query
	 * status unless we decoded at least one instruction successfully.
	 */
	memset(&insn, 0, sizeof(insn));
	memset(&iext, 0, sizeof(iext));

	/* Proceed as far as we get without trace. */
	status = pt_blk_proceed_to_insn(decoder, block, &insn, &iext,
					pt_insn_false);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		return pt_blk_proceed_with_trace(decoder, &insn, &iext);
	}

	return 0;
}

/* Proceed to the next event or decision point.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed(struct pt_block_decoder *decoder,
			  struct pt_block *block)
{
	int event_pending;

	event_pending = pt_blk_fetch_event(decoder);
	if (event_pending != 0) {
		if (event_pending < 0)
			return event_pending;

		return pt_blk_proceed_event(decoder, block);
	}

	/* The end of the trace ends a non-empty block.
	 *
	 * If we're called again, we will proceed until we really need trace.
	 * For example, if tracing is currently disabled.
	 */
	if (decoder->status & pts_eos) {
		if (!pt_blk_block_is_empty(block))
			return 0;

		if (!decoder->enabled)
			return -pte_eos;
	}

	/* If tracing is disabled and we have still trace left but no event,
	 * something is wrong.
	 */
	if (!decoder->enabled)
		return -pte_no_enable;

	return pt_blk_proceed_no_event(decoder, block);
}

static int pt_blk_status(const struct pt_block_decoder *decoder)
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

/* Try to work around erratum BDM64.
 *
 * If we got a transaction abort immediately following a branch that produced
 * trace, the trace for that branch might have been corrupted.
 *
 * Returns a positive integer if the erratum was handled.
 * Returns zero if the erratum does not seem to apply.
 * Returns a negative error code otherwise.
 */
static int pt_blk_handle_erratum_bdm64(struct pt_block_decoder *decoder,
				       const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* This only affects aborts. */
	if (!ev->variant.tsx.aborted)
		return 0;

	/* Let's check if we can reach the event location from here.
	 *
	 * If we can, let's assume the erratum did not hit.  We might still be
	 * wrong but we're not able to tell.
	 */
	if (pt_blk_ip_is_reachable(decoder, ev->variant.tsx.ip, 0x1000))
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

/* Process events that bind to the current decoder IP.
 *
 * We filled a block and proceeded to the next IP, which will become the start
 * IP of the next block.  Process any pending events that bind to that IP so we
 * can indicate their effect in the current block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_process_trailing_events(struct pt_block_decoder *decoder,
					  struct pt_block *block)
{
	struct pt_event *ev;
	int event_pending, status;

	if (!decoder)
		return -pte_internal;

	event_pending = pt_blk_fetch_event(decoder);
	if (event_pending <= 0) {
		if (event_pending < 0)
			return event_pending;

		return pt_blk_status(decoder);
	}

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_enabled:
	case ptev_disabled:
	case ptev_paging:
	case ptev_vmcs:
	case ptev_overflow:
		break;

	case ptev_async_disabled:
		if (decoder->ip != ev->variant.async_disabled.at)
			break;

		if (decoder->query.config.errata.skd022) {
			status = pt_blk_handle_erratum_skd022(decoder, ev);
			if (status != 0) {
				if (status < 0)
					break;

				return pt_blk_process_trailing_events(decoder,
								      block);
			}
		}

		return pt_blk_process_trailing_disabled(decoder, block, ev);

	case ptev_async_branch:
		if (decoder->ip != ev->variant.async_branch.from)
			break;

		return pt_blk_process_trailing_async_branch(decoder, block, ev);

	case ptev_async_paging:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_paging.ip)
			break;

		return pt_blk_process_trailing_paging(decoder, block, ev);

	case ptev_async_vmcs:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_vmcs.ip)
			break;

		return pt_blk_process_trailing_vmcs(decoder, block, ev);

	case ptev_exec_mode:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.exec_mode.ip)
			break;

		return pt_blk_process_trailing_exec_mode(decoder, block, ev);

	case ptev_tsx:
		if (!ev->ip_suppressed) {
			if (decoder->query.config.errata.bdm64) {
				status = pt_blk_handle_erratum_bdm64(decoder,
								     ev);
				if (status < 0)
					break;
			}

			if (decoder->ip != ev->variant.tsx.ip)
				break;
		}

		return pt_blk_process_trailing_tsx(decoder, block, ev);

	case ptev_stop:
		return pt_blk_process_trailing_stop(decoder, block, ev);
	}

	return pt_blk_status(decoder);
}

/* Collect one block.
 *
 * Fill a new, empty block.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_collect(struct pt_block_decoder *decoder,
			  struct pt_block *block)
{
	int errcode;

	if (!decoder || !block)
		return -pte_internal;

	/* Zero-initialize the block in case of error returns. */
	memset(block, 0, sizeof(*block));

	/* Fill in a few things from the current decode state.
	 *
	 * This reflects the state of the last pt_blk_next() or pt_blk_start()
	 * call.  Note that, unless we stop with tracing disabled, we proceed
	 * already to the start IP of the next block.
	 *
	 * Some of the state may later be overwritten as we process events.
	 */
	block->ip = decoder->ip;
	block->mode = decoder->mode;
	if (decoder->speculative)
		block->speculative = 1;

	/* Proceed one block. */
	errcode = pt_blk_proceed(decoder, block);
	if (errcode < 0)
		return errcode;

	/* We may still have events left that trigger on the current IP.
	 *
	 * This IP lies outside of @block but events typically bind to the IP of
	 * the last instruction that did not retire.
	 */
	return pt_blk_process_trailing_events(decoder, block);
}

int pt_blk_next(struct pt_block_decoder *decoder, struct pt_block *ublock,
		size_t size)
{
	struct pt_block block, *pblock;
	int errcode, status;

	if (!decoder || !ublock)
		return -pte_invalid;

	pblock = size == sizeof(block) ? ublock : &block;

	status = pt_blk_collect(decoder, pblock);

	errcode = block_to_user(ublock, size, pblock);
	if (errcode < 0)
		return errcode;

	return status;
}
