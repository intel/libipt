/*
 * Copyright (c) 2016-2022, Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
#include "pt_block_cache.h"
#include "pt_section.h"
#include "pt_image.h"
#include "pt_insn.h"
#include "pt_ild.h"
#include "pt_config.h"
#include "pt_compiler.h"

#include "intel-pt.h"

#include <string.h>
#include <stdlib.h>


static int pt_blk_proceed_no_event(struct pt_block_decoder *,
				   struct pt_block *);


/* Release a cached section.
 *
 * If @scache does not contain a section, this does noting.
 *
 * Returns zero on success, a negative error code otherwise.
 * Returns -pte_internal, if @scache is NULL.
 */
static int pt_blk_scache_invalidate(struct pt_cached_section *scache)
{
	struct pt_section *section;
	int errcode;

	if (!scache)
		return -pte_internal;

	section = scache->section;
	if (!section)
		return 0;

	errcode = pt_section_unmap(section);
	if (errcode < 0)
		return errcode;

	scache->section = NULL;

	return pt_section_put(section);
}

/* Cache @section loaded at @laddr identified by @isid in @scache.
 *
 * The caller transfers its use- and map-count to @scache.
 *
 * Returns zero on success, a negative error code otherwise.
 * Returns -pte_internal if @scache or @section is NULL.
 * Returns -pte_internal if another section is already cached.
 */
static int pt_blk_cache_section(struct pt_cached_section *scache,
				struct pt_section *section, uint64_t laddr,
				int isid)
{
	if (!scache || !section)
		return -pte_internal;

	if (scache->section)
		return -pte_internal;

	scache->section = section;
	scache->laddr = laddr;
	scache->isid = isid;

	return 0;
}

/* Get @scache's cached section.
 *
 * Check whether @scache contains a section that an image lookup of @ip in @asid
 * would return.  On success, provides the cached section in @psection and its
 * load address in @pladdr.
 *
 * Returns the section's identifier on success, a negative error code otherwise.
 * Returns -pte_internal if @scache, @psection, or @pladdr is NULL.
 * Returns -pte_nomap if @scache does not have a section cached.
 * Returns -pte_nomap if @scache's cached section does not contain @ip.
 */
static int pt_blk_cached_section(struct pt_cached_section *scache,
				 struct pt_section **psection, uint64_t *pladdr,
				 struct pt_image *image, struct pt_asid *asid,
				 uint64_t ip)
{
	struct pt_section *section;
	uint64_t laddr;
	int isid, errcode;

	if (!scache || !psection || !pladdr)
		return -pte_internal;


	section = scache->section;
	laddr = scache->laddr;
	isid = scache->isid;
	if (!section)
		return -pte_nomap;

	errcode = pt_image_validate(image, asid, ip, section, laddr, isid);
	if (errcode < 0)
		return errcode;

	*psection = section;
	*pladdr = laddr;

	return isid;
}

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

/* Initialize the query decoder flags based on our flags. */

static int pt_blk_init_qry_flags(struct pt_conf_flags *qflags,
				 const struct pt_conf_flags *flags)
{
	if (!qflags || !flags)
		return -pte_internal;

	memset(qflags, 0, sizeof(*qflags));

	return 0;
}

int pt_blk_decoder_init(struct pt_block_decoder *decoder,
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
	errcode = pt_blk_init_qry_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	errcode = pt_qry_decoder_init(&decoder->query, &config);
	if (errcode < 0)
		return errcode;

	pt_image_init(&decoder->default_image, NULL);
	decoder->image = &decoder->default_image;

	memset(&decoder->scache, 0, sizeof(decoder->scache));

	pt_blk_reset(decoder);

	return 0;
}

void pt_blk_decoder_fini(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	/* Release the cached section so we don't leak it. */
	(void) pt_blk_scache_invalidate(&decoder->scache);

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
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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

/* Process an overflow event.
 *
 * An overflow ends a non-empty block.  The overflow itself is indicated in the
 * next block.  Indicate the overflow and resume in this case.
 *
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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
 * Returns a positive integer if the event has been processed.
 * Returns zero if the event shall be postponed.
 * Returns a negative error code otherwise.
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

	return 1;
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

/* Set the expected resume address for a synchronous disable.
 *
 * On a synchronous disable, @decoder->ip still points to the instruction to
 * which the event bound.  That's not where we expect tracing to resume.
 *
 * For calls, a fair assumption is that tracing resumes after returning from the
 * called function.  For other types of instructions, we simply don't know.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_blk_set_disable_resume_ip(struct pt_block_decoder *decoder,
					const struct pt_insn *insn)
{
	if (!decoder || !insn)
		return -pte_internal;

	switch (insn->iclass) {
	case ptic_call:
	case ptic_far_call:
		decoder->ip = insn->ip + insn->size;
		break;

	default:
		decoder->ip = 0ull;
		break;
	}

	return 0;
}

/* Proceed from an instruction.
 *
 * Set @decoder->ip to the next instruction past @insn/@iext.
 *
 * Returns a positive integer if we did not need trace.
 * Returns zero if we needed trace to proceed.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_blk_proceed_from_insn(struct pt_block_decoder *decoder,
				    const struct pt_insn *insn,
				    const struct pt_insn_ext *iext)
{
	int status;

	if (!decoder)
		return -pte_internal;

	/* There's nothing to do if tracing got disabled. */
	if (!decoder->enabled)
		return 1;

	status = pt_insn_next_ip(&decoder->ip, insn, iext);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		return pt_blk_proceed_with_trace(decoder, insn, iext);
	}

	return 1;
}

/* Decode one instruction in a known section.
 *
 * Decode the instruction at @insn->ip in @section loaded at @laddr assuming
 * execution mode @insn->mode.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_decode_in_section(struct pt_insn *insn,
				    struct pt_insn_ext *iext,
				    const struct pt_section *section,
				    uint64_t laddr)
{
	int status;

	if (!insn || !iext)
		return -pte_internal;

	/* We know that @ip is contained in @section.
	 *
	 * Note that we need to translate @ip into a section offset.
	 */
	status = pt_section_read(section, insn->raw, sizeof(insn->raw),
				 insn->ip - laddr);
	if (status < 0)
		return status;

	/* We initialize @insn->size to the maximal possible size.  It will be
	 * set to the actual size during instruction decode.
	 */
	insn->size = (uint8_t) status;

	return pt_ild_decode(insn, iext);
}

/* Update the return-address stack if @insn is a near call.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static inline int pt_blk_log_call(struct pt_block_decoder *decoder,
				  const struct pt_insn *insn,
				  const struct pt_insn_ext *iext)
{
	if (!decoder || !insn || !iext)
		return -pte_internal;

	if (insn->iclass != ptic_call)
		return 0;

	/* Ignore direct calls to the next instruction that are used for
	 * position independent code.
	 */
	if (iext->variant.branch.is_direct &&
	    !iext->variant.branch.displacement)
		return 0;

	return pt_retstack_push(&decoder->retstack, insn->ip + insn->size);
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

	/* The truncated instruction must be last. */
	if (block->truncated)
		return 0;

	memset(&insn, 0, sizeof(insn));
	memset(&iext, 0, sizeof(iext));

	insn.mode = decoder->mode;
	insn.ip = decoder->ip;

	status = pt_insn_decode(&insn, &iext, decoder->image, &decoder->asid);
	if (status < 0)
		return status;

	/* We do not switch sections inside a block. */
	if (insn.isid != block->isid) {
		if (!pt_blk_block_is_empty(block))
			return 0;

		block->isid = insn.isid;
	}

	/* If we couldn't read @insn's memory in one chunk from @insn.isid, we
	 * provide the memory in @block.
	 */
	if (insn.truncated) {
		memcpy(block->raw, insn.raw, insn.size);
		block->size = insn.size;
		block->truncated = 1;
	}

	/* Log calls' return addresses for return compression. */
	status = pt_blk_log_call(decoder, &insn, &iext);
	if (status < 0)
		return status;

	/* We have a new instruction. */
	block->iclass = insn.iclass;
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

	if (!decoder || !insn || !predicate)
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

		/* End the block if the user asked us to.
		 *
		 * We only need to take care about direct near calls.  Indirect
		 * and far calls require trace and will naturally end a block.
		 */
		if (decoder->flags.variant.block.end_on_call &&
		    (insn->iclass == ptic_call))
			return 0;
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

	if (!decoder || !insn)
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

		/* End the block if the user asked us to.
		 *
		 * We only need to take care about direct near calls.  Indirect
		 * and far calls require trace and will naturally end a block.
		 *
		 * The call at the end of the block may have reached @ip; make
		 * sure to indicate that.
		 */
		if (decoder->flags.variant.block.end_on_call &&
		    (insn->iclass == ptic_call)) {
			return (decoder->ip == ip ? 1 : 0);
		}
	}
}

/* Proceed to a particular IP with trace, if necessary.
 *
 * Proceed until we reach @ip or until:
 *
 *   - @block is full:               return zero
 *   - @block would switch sections: return zero
 *   - we need trace:                return zero
 *
 * Update @decoder->ip to point to the last IP that was reached.
 *
 * A return of zero ends @block.
 *
 * Returns a positive integer if @ip was reached.
 * Returns zero if no such instruction was reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_ip_with_trace(struct pt_block_decoder *decoder,
					   struct pt_block *block,
					   uint64_t ip)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int status;

	/* Try to reach @ip without trace.
	 *
	 * We're also OK if @block overflowed or we switched sections and we
	 * have to try again in the next iteration.
	 */
	status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext, ip);
	if (status != -pte_bad_query)
		return status;

	/* Needing trace is not an error.  We use trace to determine the next
	 * start IP and end the block.
	 */
	return pt_blk_proceed_with_trace(decoder, &insn, &iext);
}

/* Proceed for a synchronous disable starting at the current instruction.
 *
 * We are processing events at @insn/@iext and have a (synchronous) disabled
 * event pending.  This event may bind to @insn/@iext, as well.  Check if it
 * does and, if not, proceed past @insn/@iext.
 *
 * Returns zero if @ev binds to @insn/@iext.
 * Returns a positive integer if we proceeded past @insn/@iext.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_blk_proceed_disabled_insn(struct pt_block_decoder *decoder,
					const struct pt_insn *insn,
					const struct pt_insn_ext *iext,
					const struct pt_event *ev)
{
	int status;

	if (!decoder || !ev)
		return -pte_internal;

	if (ev->ip_suppressed && pt_insn_changes_cr3(insn, iext))
		return 0;

	/* A synchronous disable event also binds to the next indirect or
	 * conditional branch, i.e. to any branch that would have required
	 * trace.
	 */
	status = pt_insn_next_ip(&decoder->ip, insn, iext);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		return pt_blk_set_disable_resume_ip(decoder, insn);
	}

	return 1;
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

	case ptic_other:
		return pt_insn_changes_cr3(insn, iext);
	}
}

/* Proceed to the location of a synchronous disabled event with suppressed IP
 * considering SKL014.
 *
 * We have a (synchronous) disabled event pending.  Proceed to the event
 * location and indicate whether we were able to reach it.
 *
 * With SKL014 a TIP.PGD with suppressed IP may also be generated by a direct
 * unconditional branch that clears FilterEn by jumping out of a filter region
 * or into a TraceStop region.  Use the filter configuration to determine the
 * exact branch the event binds to.
 *
 * The last instruction that was reached is stored in @insn/@iext.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_skl014(struct pt_block_decoder *decoder,
				 struct pt_block *block, struct pt_insn *insn,
				 struct pt_insn_ext *iext)
{
	const struct pt_conf_addr_filter *addr_filter;
	int status;

	if (!decoder || !block || !insn || !iext)
		return -pte_internal;

	addr_filter = &decoder->query.config.addr_filter;
	for (;;) {
		uint64_t ip;

		status = pt_blk_proceed_to_insn(decoder, block, insn, iext,
						pt_insn_skl014);
		if (status <= 0)
			break;

		/* The erratum doesn't apply if we can bind the event to a
		 * CR3-changing instruction.
		 */
		if (pt_insn_changes_cr3(insn, iext))
			break;

		/* Check the filter against the branch target. */
		status = pt_insn_next_ip(&ip, insn, iext);
		if (status < 0)
			break;

		status = pt_filter_addr_check(addr_filter, ip);
		if (status <= 0) {
			/* We need to flip the indication.
			 *
			 * We reached the event location when @ip lies inside a
			 * tracing-disabled region.
			 */
			if (!status)
				status = 1;

			break;
		}

		/* This is not the correct instruction.  Proceed past it and try
		 * again.
		 */
		decoder->ip = ip;

		/* End the block if the user asked us to.
		 *
		 * We only need to take care about direct near calls.  Indirect
		 * and far calls require trace and will naturally end a block.
		 */
		if (decoder->flags.variant.block.end_on_call &&
		    (insn->iclass == ptic_call))
			break;
	}

	return status;
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
	int status;

	if (!decoder || !block || !ev)
		return -pte_internal;


	if (ev->ip_suppressed) {
		/* A synchronous disabled event also binds to far branches and
		 * CPL-changing instructions.  Both would require trace,
		 * however, and are thus implicitly handled by erroring out.
		 */

		/* Due to SKL014 the TIP.PGD payload may be suppressed also for
		 * direct branches.
		 *
		 * If we don't have a filter configuration we assume that no
		 * address filters were used and the erratum does not apply.
		 *
		 * We might otherwise disable tracing too early.
		 */
		if (decoder->query.config.addr_filter.config.addr_cfg &&
		    decoder->query.config.errata.skl014)
			status = pt_blk_proceed_skl014(decoder, block, insn,
						       iext);
		else
			status = pt_blk_proceed_to_insn(decoder, block, insn,
							iext,
							pt_insn_changes_cr3);
	} else
		status = pt_blk_proceed_to_ip(decoder, block, insn, iext,
					      ev->variant.disabled.ip);

	/* A synchronous disable event also binds to the next indirect or
	 * conditional branch, i.e. to any branch that would have required
	 * trace.
	 */
	if (status == -pte_bad_query) {
		status = pt_blk_set_disable_resume_ip(decoder, insn);
		if (status < 0)
			return status;

		return 1;
	}

	return status;
}

/* Proceed to the event location for an async paging event.
 *
 * We have an async paging event pending.  Proceed to the event location and
 * indicate whether we were able to reach it.  Needing trace in order to proceed
 * is not an error in this case but ends the block.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_async_paging(struct pt_block_decoder *decoder,
					  struct pt_block *block,
					  const struct pt_event *ev)
{
	if (!ev)
		return -pte_internal;

	/* Apply the event immediately if we don't have an IP. */
	if (ev->ip_suppressed)
		return 1;

	return pt_blk_proceed_to_ip_with_trace(decoder, block,
					       ev->variant.async_paging.ip);
}

/* Proceed to the event location for an async vmcs event.
 *
 * We have an async vmcs event pending.  Proceed to the event location and
 * indicate whether we were able to reach it.  Needing trace in order to proceed
 * is not an error in this case but ends the block.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_async_vmcs(struct pt_block_decoder *decoder,
					struct pt_block *block,
					const struct pt_event *ev)
{
	if (!ev)
		return -pte_internal;

	/* Apply the event immediately if we don't have an IP. */
	if (ev->ip_suppressed)
		return 1;

	return pt_blk_proceed_to_ip_with_trace(decoder, block,
					       ev->variant.async_vmcs.ip);
}

/* Proceed to the event location for an exec mode event.
 *
 * We have an exec mode event pending.  Proceed to the event location and
 * indicate whether we were able to reach it.  Needing trace in order to proceed
 * is not an error in this case but ends the block.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_exec_mode(struct pt_block_decoder *decoder,
				       struct pt_block *block,
				       const struct pt_event *ev)
{
	if (!ev)
		return -pte_internal;

	/* Apply the event immediately if we don't have an IP. */
	if (ev->ip_suppressed)
		return 1;

	return pt_blk_proceed_to_ip_with_trace(decoder, block,
					       ev->variant.exec_mode.ip);
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
	int errcode;

	if (!decoder || !ev)
		return -pte_internal;

	insn.mode = decoder->mode;
	insn.ip = ev->variant.async_disabled.at;

	errcode = pt_insn_decode(&insn, &iext, decoder->image, &decoder->asid);
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
	int process_insn, bound_paging, bound_vmcs;

	if (!decoder || !block)
		return -pte_internal;

	/* When non-zero, @process_insn indicates that we are processing
	 * @insn/@iext.  We bound one or more events to it and are looking for
	 * further events to bind to it.
	 *
	 * When we find an event that does not bind to @insn/@iext, proceed from
	 * @insn/@iext and clear the below flags.
	 */
	process_insn = 0;
	bound_paging = 0;
	bound_vmcs = 0;
	for (;;) {
		struct pt_insn_ext iext;
		struct pt_insn insn;
		struct pt_event *ev;
		uint64_t ip;
		int status;

		if (!decoder->process_event)
			return -pte_internal;

		ev = &decoder->event;
		switch (ev->type) {
		case ptev_enabled:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_process_enabled(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_disabled:
			if (process_insn) {
				status = pt_blk_proceed_disabled_insn(decoder,
								      &insn,
								      &iext,
								      ev);

				if (status <= 0) {
					if (status < 0)
						return status;

					status =
						pt_blk_process_disabled(decoder,
									block,
									ev);
					if (status <= 0)
						return status;

					/* We don't need a bound_disabled.
					 * Duplicate disable events are
					 * diagnosed when applying the event.
					 */
					break;
				} else {
					/* We proceeded past @insn/@iext. */
					process_insn = 0;
					bound_paging = 0;
					bound_vmcs = 0;
				}
			}

			status = pt_blk_proceed_to_disabled(decoder, block,
							    &insn, &iext, ev);
			if (status <= 0)
				return status;

			status = pt_blk_process_disabled(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_async_disabled:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			ip = ev->variant.async_disabled.at;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				return status;

			if (decoder->query.config.errata.skd022) {
				status = pt_blk_handle_erratum_skd022(decoder,
								      ev);
				if (status != 0) {
					if (status < 0)
						return status;

					/* If the erratum hits, we modify the
					 * event.  Try again.
					 */
					continue;
				}
			}

			status = pt_blk_process_disabled(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_async_branch:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			ip = ev->variant.async_branch.from;

			status = pt_blk_proceed_to_ip(decoder, block, &insn,
						      &iext, ip);
			if (status <= 0)
				return status;

			status = pt_blk_process_async_branch(decoder, block,
							     ev);
			if (status <= 0)
				return status;

			break;

		case ptev_paging:
			if (!decoder->enabled) {
				status = pt_blk_apply_paging(decoder, block,
							     ev);
				if (status < 0)
					return status;

				break;
			}

			if (process_insn) {
				if (!bound_paging &&
				    pt_insn_binds_to_pip(&insn, &iext)) {

					status = pt_blk_apply_paging(decoder,
								     block, ev);
					if (status < 0)
						return status;

					bound_paging = 1;
					break;
				}

				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_proceed_to_insn(decoder, block, &insn,
							&iext,
							pt_insn_binds_to_pip);
			if (status <= 0)
				return status;

			status = pt_blk_apply_paging(decoder, block, ev);
			if (status < 0)
				return status;

			process_insn = 1;
			bound_paging = 1;

			break;

		case ptev_async_paging:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_proceed_to_async_paging(decoder, block,
								ev);
			if (status <= 0)
				return status;

			status = pt_blk_apply_paging(decoder, block, ev);
			if (status < 0)
				return status;

			break;

		case ptev_vmcs:
			if (!decoder->enabled) {
				status = pt_blk_apply_vmcs(decoder, block, ev);
				if (status < 0)
					return status;

				break;
			}

			if (process_insn) {
				if (!bound_vmcs &&
				    pt_insn_binds_to_vmcs(&insn, &iext)) {

					status = pt_blk_apply_vmcs(decoder,
								   block, ev);
					if (status < 0)
						return status;

					bound_vmcs = 1;
					break;
				}

				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_proceed_to_insn(decoder, block, &insn,
							&iext,
							pt_insn_binds_to_vmcs);
			if (status <= 0)
				return status;

			status = pt_blk_apply_vmcs(decoder, block, ev);
			if (status < 0)
				return status;

			process_insn = 1;
			bound_vmcs = 1;

			break;

		case ptev_async_vmcs:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_proceed_to_async_vmcs(decoder, block,
							      ev);
			if (status <= 0)
				return status;

			status = pt_blk_apply_vmcs(decoder, block, ev);
			if (status < 0)
				return status;

			break;

		case ptev_overflow:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_process_overflow(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_exec_mode:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			status = pt_blk_proceed_to_exec_mode(decoder, block,
							     ev);
			if (status <= 0)
				return status;

			status = pt_blk_process_exec_mode(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_tsx:
			/* This event does not bind to an instruction. */
			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status < 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;
			}

			if (!ev->ip_suppressed) {
				ip = ev->variant.tsx.ip;

				status = pt_blk_proceed_to_ip(decoder, block,
							      &insn, &iext, ip);
				if (status <= 0)
					return status;
			}

			status = pt_blk_process_tsx(decoder, block, ev);
			if (status <= 0)
				return status;

			break;

		case ptev_stop:
			status = pt_blk_apply_stop(decoder, block, ev);
			if (status < 0)
				return status;

			break;
		}

		/* We should have processed the event.  If we have not, we might
		 * spin here forever.
		 */
		if (decoder->process_event)
			return -pte_internal;

		/* Check if we have more events pending. */
		status = pt_blk_fetch_event(decoder);
		if (status <= 0) {
			if (status < 0)
				return status;

			if (process_insn) {
				status = pt_blk_proceed_from_insn(decoder,
								  &insn, &iext);
				if (status <= 0)
					return status;

				process_insn = 0;
				bound_paging = 0;
				bound_vmcs = 0;

				/* Check again now that we proceeded past the
				 * current instruction.
				 */
				status = pt_blk_fetch_event(decoder);
				if (status != 0) {
					if (status < 0)
						return status;

					continue;
				}
			}

			break;
		}
	}

	return pt_blk_proceed_no_event(decoder, block);
}

/* Proceed to the next decision point without using the block cache.
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
static int pt_blk_proceed_no_event_uncached(struct pt_block_decoder *decoder,
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

/* Check if @ip is contained in @section loaded at @laddr.
 *
 * Returns non-zero if it is.
 * Returns zero if it isn't or of @section is NULL.
 */
static inline int pt_blk_is_in_section(uint64_t ip,
				       const struct pt_section *section,
				       uint64_t laddr)
{
	uint64_t begin, end;

	begin = laddr;
	end = begin + pt_section_size(section);

	return (begin <= ip && ip < end);
}

/* Insert a trampoline block cache entry.
 *
 * Add a trampoline block cache entry at @ip to continue at @nip, where @nip
 * must be the next instruction after @ip.
 *
 * Both @ip and @nip must be section-relative
 *
 * Returns zero on success, a negative error code otherwise.
 */
static inline int pt_blk_add_trampoline(struct pt_block_cache *bcache,
					uint64_t ip, uint64_t nip,
					enum pt_exec_mode mode)
{
	struct pt_bcache_entry bce;
	int64_t disp;

	/* The displacement from @ip to @nip for the trampoline. */
	disp = (int64_t) (nip - ip);

	memset(&bce, 0, sizeof(bce));
	bce.displacement = (int32_t) disp;
	bce.ninsn = 1;
	bce.mode = mode;
	bce.qualifier = ptbq_again;

	/* If we can't reach @nip without overflowing the displacement field, we
	 * have to stop and re-decode the instruction at @ip.
	 */
	if ((int64_t) bce.displacement != disp) {

		memset(&bce, 0, sizeof(bce));
		bce.ninsn = 1;
		bce.mode = mode;
		bce.qualifier = ptbq_decode;
	}

	return pt_bcache_add(bcache, ip, bce);
}

enum {
	/* The maximum number of steps when filling the block cache. */
	bcache_fill_steps	= 0x400
};

/* Proceed to the next instruction and fill the block cache for @decoder->ip.
 *
 * Tracing is enabled and we don't have an event pending.  The current IP is not
 * yet cached.
 *
 * Proceed one instruction without using the block cache, then try to proceed
 * further using the block cache.
 *
 * On our way back, add a block cache entry for the IP before proceeding.  Note
 * that the recursion is bounded by @steps and ultimately by the maximum number
 * of instructions in a block.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_no_event_fill_cache(struct pt_block_decoder *decoder,
					      struct pt_block *block,
					      struct pt_block_cache *bcache,
					      struct pt_section *section,
					      uint64_t laddr, size_t steps)
{
	struct pt_bcache_entry bce;
	struct pt_insn_ext iext;
	struct pt_insn insn;
	uint64_t nip, dip;
	int64_t disp;
	int status;

	if (!decoder || !steps)
		return -pte_internal;

	/* Proceed one instruction by decoding and examining it.
	 *
	 * Note that we also return on a status of zero that indicates that the
	 * instruction didn't fit into @block.
	 */
	status = pt_blk_proceed_one_insn(decoder, block, &insn, &iext);
	if (status <= 0)
		return status;

	/* Let's see if we can proceed to the next IP without trace.
	 *
	 * If we can't, this is certainly a decision point.
	 */
	status = pt_insn_next_ip(&decoder->ip, &insn, &iext);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		memset(&bce, 0, sizeof(bce));
		bce.ninsn = 1;
		bce.mode = insn.mode;
		bce.isize = insn.size;

		/* Clear the instruction size in case of overflows. */
		if ((uint8_t) bce.isize != insn.size)
			bce.isize = 0;

		switch (insn.iclass) {
		case ptic_error:
		case ptic_other:
			return -pte_internal;

		case ptic_jump:
			/* A direct jump doesn't require trace. */
			if (iext.variant.branch.is_direct)
				return -pte_internal;

			bce.qualifier = ptbq_indirect;
			break;

		case ptic_call:
			/* A direct call doesn't require trace. */
			if (iext.variant.branch.is_direct)
				return -pte_internal;

			bce.qualifier = ptbq_ind_call;
			break;

		case ptic_return:
			bce.qualifier = ptbq_return;
			break;

		case ptic_cond_jump:
			bce.qualifier = ptbq_cond;
			break;

		case ptic_far_call:
		case ptic_far_return:
		case ptic_far_jump:
			bce.qualifier = ptbq_indirect;
			break;
		}

		/* If the block was truncated, we have to decode its last
		 * instruction each time.
		 *
		 * We could have skipped the above switch and size assignment in
		 * this case but this is already a slow and hopefully infrequent
		 * path.
		 */
		if (block->truncated)
			bce.qualifier = ptbq_decode;

		status = pt_bcache_add(bcache, insn.ip - laddr, bce);
		if (status < 0)
			return status;

		return pt_blk_proceed_with_trace(decoder, &insn, &iext);
	}

	/* The next instruction's IP. */
	nip = decoder->ip;

	/* Even if we were able to proceed without trace, we might have to stop
	 * here for various reasons:
	 *
	 *   - at near direct calls to update the return-address stack
	 *
	 *     We are forced to re-decode @insn to get the branch displacement.
	 *
	 *     Even though it is constant, we don't cache it to avoid increasing
	 *     the size of a cache entry.  Note that the displacement field is
	 *     zero for this entry and we might be tempted to use it - but other
	 *     entries that point to this decision point will have non-zero
	 *     displacement.
	 *
	 *     We could proceed after a near direct call but we migh as well
	 *     postpone it to the next iteration.  Make sure to end the block if
	 *     @decoder->flags.variant.block.end_on_call is set, though.
	 *
	 *   - if we switched sections
	 *
	 *     This ends a block just like a branch that requires trace.
	 *
	 *     We need to re-decode @insn in order to determine the start IP of
	 *     the next block.
	 *
	 *   - if the block is truncated
	 *
	 *     We need to read the last instruction's memory from multiple
	 *     sections and provide it to the user.
	 *
	 *     We could still use the block cache but then we'd have to handle
	 *     this case for each qualifier.  Truncation is hopefully rare and
	 *     having to read the memory for the instruction from multiple
	 *     sections is already slow.  Let's rather keep things simple and
	 *     route it through the decode flow, where we already have
	 *     everything in place.
	 */
	if (insn.iclass == ptic_call ||
	    !pt_blk_is_in_section(nip, section, laddr) || block->truncated) {

		memset(&bce, 0, sizeof(bce));
		bce.ninsn = 1;
		bce.mode = insn.mode;
		bce.qualifier = ptbq_decode;

		return pt_bcache_add(bcache, insn.ip - laddr, bce);
	}

	/* We proceeded one instruction.  Let's see if we have a cache entry for
	 * the next instruction.
	 */
	status = pt_bcache_lookup(&bce, bcache, nip - laddr);
	if (status < 0)
		return status;

	/* If we don't have a valid cache entry, yet, fill the cache some more.
	 *
	 * On our way back, we add a cache entry for this instruction based on
	 * the cache entry of the succeeding instruction.
	 */
	if (!pt_bce_is_valid(bce)) {
		/* If we exceeded the maximum number of allowed steps, we insert
		 * a trampoline to the next instruction.
		 *
		 * The next time we encounter the same code, we will use the
		 * trampoline to jump directly to where we left off this time
		 * and continue from there.
		 */
		steps -= 1;
		if (!steps)
			return pt_blk_add_trampoline(bcache, insn.ip - laddr,
						     nip - laddr, insn.mode);

		status = pt_blk_proceed_no_event_fill_cache(decoder, block,
							    bcache, section,
							    laddr, steps);
		if (status < 0)
			return status;

		/* Let's see if we have more luck this time. */
		status = pt_bcache_lookup(&bce, bcache, nip - laddr);
		if (status < 0)
			return status;

		/* If we still don't have a valid cache entry, we're done.  Most
		 * likely, @block overflowed and we couldn't proceed past the
		 * next instruction.
		 */
		if (!pt_bce_is_valid(bce))
			return 0;
	}

	/* We must not have switched execution modes.
	 *
	 * This would require an event and we're on the no-event flow.
	 */
	if (pt_bce_exec_mode(bce) != insn.mode)
		return -pte_internal;

	/* The decision point IP and the displacement from @insn.ip. */
	dip = nip + bce.displacement;
	disp = (int64_t) (dip - insn.ip);

	/* We must not have switched sections between @nip and @dip since the
	 * cache entry at @nip brought us to @dip.
	 */
	if (!pt_blk_is_in_section(dip, section, laddr))
		return -pte_internal;

	/* Let's try to reach @nip's decision point from @insn.ip.
	 *
	 * There are two fields that may overflow: @bce.ninsn and
	 * @bce.displacement.
	 */
	bce.ninsn += 1;
	bce.displacement = (int32_t) disp;

	/* If none of them overflowed, we're done.
	 *
	 * If one or both overflowed, let's try to insert a trampoline, i.e. we
	 * try to reach @dip via a ptbq_again entry to @nip.
	 */
	if (!bce.ninsn || ((int64_t) bce.displacement != disp))
		return pt_blk_add_trampoline(bcache, insn.ip - laddr,
					     nip - laddr, insn.mode);

	/* We're done.  Add the cache entry.
	 *
	 * There's a chance that other decoders updated the cache entry in the
	 * meantime.  They should have come to the same conclusion as we,
	 * though, and the cache entries should be identical.
	 *
	 * Cache updates are atomic so even if the two versions were not
	 * identical, we wouldn't care because they are both correct.
	 */
	return pt_bcache_add(bcache, insn.ip - laddr, bce);
}

/* Proceed at a potentially truncated instruction.
 *
 * We were not able to decode the instruction at @decoder->ip in @decoder's
 * cached section.  This is typically caused by not having enough bytes.
 *
 * Try to decode the instruction again using the entire image.  If this succeeds
 * we expect to end up with an instruction that was truncated in the section it
 * started.  We provide the full instruction in this case and end the block.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_truncated(struct pt_block_decoder *decoder,
				    struct pt_block *block)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int errcode;

	if (!decoder || !block)
		return -pte_internal;

	memset(&iext, 0, sizeof(iext));
	memset(&insn, 0, sizeof(insn));

	insn.mode = decoder->mode;
	insn.ip = decoder->ip;

	errcode = pt_insn_decode(&insn, &iext, decoder->image, &decoder->asid);
	if (errcode < 0)
		return errcode;

	/* We shouldn't use this function if the instruction isn't truncated. */
	if (!insn.truncated)
		return -pte_internal;

	/* Provide the instruction in the block.  This ends the block. */
	memcpy(block->raw, insn.raw, insn.size);
	block->iclass = insn.iclass;
	block->size = insn.size;
	block->truncated = 1;

	/* Log calls' return addresses for return compression. */
	errcode = pt_blk_log_call(decoder, &insn, &iext);
	if (errcode < 0)
		return errcode;

	/* Let's see if we can proceed to the next IP without trace.
	 *
	 * The truncated instruction ends the block but we still need to get the
	 * next block's start IP.
	 */
	errcode = pt_insn_next_ip(&decoder->ip, &insn, &iext);
	if (errcode < 0) {
		if (errcode != -pte_bad_query)
			return errcode;

		return pt_blk_proceed_with_trace(decoder, &insn, &iext);
	}

	return 0;
}

/* Proceed to the next decision point using the block cache.
 *
 * Tracing is enabled and we don't have an event pending.  We already set
 * @block's isid.  All reads are done within @section as we're not switching
 * sections between blocks.
 *
 * Proceed as far as we get without trace.  Stop when we either:
 *
 *   - need trace in order to continue
 *   - overflow the max number of instructions in a block
 *
 * We actually proceed one instruction further to get the start IP for the next
 * block.  This only updates @decoder's internal state, though.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_no_event_cached(struct pt_block_decoder *decoder,
					  struct pt_block *block,
					  struct pt_block_cache *bcache,
					  struct pt_section *section,
					  uint64_t laddr)
{
	struct pt_bcache_entry bce;
	uint16_t binsn, ninsn;
	int status;

	if (!decoder || !block)
		return -pte_internal;

	status = pt_bcache_lookup(&bce, bcache, decoder->ip - laddr);
	if (status < 0)
		return status;

	/* If we don't find a valid cache entry, fill the cache. */
	if (!pt_bce_is_valid(bce))
		return pt_blk_proceed_no_event_fill_cache(decoder, block,
							  bcache, section,
							  laddr,
							  bcache_fill_steps);

	/* We have a valid cache entry.  Let's first check if the way to the
	 * decision point still fits into @block.
	 *
	 * If it doesn't, we end the block without filling it as much as we
	 * could since this would require us to switch to the slow path.
	 *
	 * On the next iteration, we will start with an empty block, which is
	 * guaranteed to have enough room for at least one block cache entry.
	 */
	binsn = block->ninsn;
	ninsn = binsn + (uint16_t) bce.ninsn;
	if (ninsn < binsn)
		return 0;

	/* Jump ahead to the decision point and proceed from there.
	 *
	 * We're not switching execution modes so even if @block already has an
	 * execution mode, it will be the one we're going to set.
	 */
	decoder->ip += bce.displacement;

	/* We don't know the instruction class so we should be setting it to
	 * ptic_error.  Since we will be able to fill it back in later in most
	 * cases, we move the clearing to the switch cases that don't.
	 */
	block->end_ip = decoder->ip;
	block->ninsn = ninsn;
	block->mode = pt_bce_exec_mode(bce);


	switch (pt_bce_qualifier(bce)) {
	case ptbq_again:
		/* We're not able to reach the actual decision point due to
		 * overflows so we inserted a trampoline.
		 *
		 * We don't know the instruction and it is not guaranteed that
		 * we will proceed further (e.g. if @block overflowed).  Let's
		 * clear any previously stored instruction class which has
		 * become invalid when we updated @block->ninsn.
		 */
		block->iclass = ptic_error;

		return pt_blk_proceed_no_event_cached(decoder, block, bcache,
						      section, laddr);

	case ptbq_cond:
		/* We're at a conditional branch. */
		block->iclass = ptic_cond_jump;

		/* Let's first check whether we know the size of the
		 * instruction.  If we do, we might get away without decoding
		 * the instruction.
		 *
		 * If we don't know the size we might as well do the full decode
		 * and proceed-with-trace flow we do for ptbq_decode.
		 */
		if (bce.isize) {
			uint64_t ip;
			int taken;

			/* If the branch is not taken, we don't need to decode
			 * the instruction at @decoder->ip.
			 *
			 * If it is taken, we have to implement everything here.
			 * We can't use the normal decode and proceed-with-trace
			 * flow since we already consumed the TNT bit.
			 */
			status = pt_qry_cond_branch(&decoder->query, &taken);
			if (status < 0)
				return status;

			/* Preserve the query decoder's response which indicates
			 * upcoming events.
			 */
			decoder->status = status;

			ip = decoder->ip;
			if (taken) {
				struct pt_insn_ext iext;
				struct pt_insn insn;

				memset(&iext, 0, sizeof(iext));
				memset(&insn, 0, sizeof(insn));

				insn.mode = pt_bce_exec_mode(bce);
				insn.ip = ip;

				status = pt_blk_decode_in_section(&insn, &iext,
								  section,
								  laddr);
				if (status < 0)
					return status;

				ip += iext.variant.branch.displacement;
			}

			decoder->ip = ip + bce.isize;
			break;
		}

		fallthrough;
	case ptbq_decode: {
		struct pt_insn_ext iext;
		struct pt_insn insn;

		/* We need to decode the instruction at @decoder->ip and decide
		 * what to do based on that.
		 *
		 * We already accounted for the instruction so we can't just
		 * call pt_blk_proceed_one_insn().
		 */

		memset(&iext, 0, sizeof(iext));
		memset(&insn, 0, sizeof(insn));

		insn.mode = pt_bce_exec_mode(bce);
		insn.ip = decoder->ip;

		status = pt_blk_decode_in_section(&insn, &iext, section, laddr);
		if (status < 0) {
			if (status != -pte_bad_insn)
				return status;

			return pt_blk_proceed_truncated(decoder, block);
		}

		/* We just decoded @insn so we know the instruction class. */
		block->iclass = insn.iclass;

		/* Log calls' return addresses for return compression. */
		status = pt_blk_log_call(decoder, &insn, &iext);
		if (status < 0)
			return status;

		/* Let's see if we can proceed to the next IP without trace.
		 *
		 * Note that we also stop due to displacement overflows or to
		 * maintain the return-address stack for near direct calls.
		 */
		status = pt_insn_next_ip(&decoder->ip, &insn, &iext);
		if (status < 0) {
			if (status != -pte_bad_query)
				return status;

			/* We can't, so let's proceed with trace, which
			 * completes the block.
			 */
			return pt_blk_proceed_with_trace(decoder, &insn, &iext);
		}

		/* End the block if the user asked us to.
		 *
		 * We only need to take care about direct near calls.  Indirect
		 * and far calls require trace and will naturally end a block.
		 */
		if (decoder->flags.variant.block.end_on_call &&
		    (insn.iclass == ptic_call))
			break;

		/* If we can proceed without trace and we stay in @section we
		 * may proceed further.
		 *
		 * We're done if we switch sections, though.
		 */
		if (!pt_blk_is_in_section(decoder->ip, section, laddr))
			break;

		return pt_blk_proceed_no_event_cached(decoder, block, bcache,
						      section, laddr);
	}

	case ptbq_ind_call: {
		uint64_t ip;

		/* We're at a near indirect call. */
		block->iclass = ptic_call;

		/* We need to update the return-address stack and query the
		 * destination IP.
		 */
		ip = decoder->ip;

		/* If we already know the size of the instruction, we don't need
		 * to re-decode it.
		 */
		if (bce.isize)
			ip += bce.isize;
		else {
			struct pt_insn_ext iext;
			struct pt_insn insn;

			memset(&iext, 0, sizeof(iext));
			memset(&insn, 0, sizeof(insn));

			insn.mode = pt_bce_exec_mode(bce);
			insn.ip = ip;

			status = pt_blk_decode_in_section(&insn, &iext, section,
							  laddr);
			if (status < 0)
				return status;

			ip += insn.size;
		}

		status = pt_retstack_push(&decoder->retstack, ip);
		if (status < 0)
			return status;

		status = pt_qry_indirect_branch(&decoder->query, &decoder->ip);
		if (status < 0)
			return status;

		/* Preserve the query decoder's response which indicates
		 * upcoming events.
		 */
		decoder->status = status;
		break;
	}

	case ptbq_return: {
		int taken;

		/* We're at a near return. */
		block->iclass = ptic_return;

		/* Check for a compressed return. */
		status = pt_qry_cond_branch(&decoder->query, &taken);
		if (status < 0) {
			if (status != -pte_bad_query)
				return status;

			/* The return is not compressed.  We need another query
			 * to determine the destination IP.
			 */
			status = pt_qry_indirect_branch(&decoder->query,
							&decoder->ip);
			if (status < 0)
				return status;

			/* Preserve the query decoder's response which indicates
			 * upcoming events.
			 */
			decoder->status = status;
			break;
		}

		/* Preserve the query decoder's response which indicates
		 * upcoming events.
		 */
		decoder->status = status;

		/* A compressed return is indicated by a taken conditional
		 * branch.
		 */
		if (!taken)
			return -pte_bad_retcomp;

		return pt_retstack_pop(&decoder->retstack, &decoder->ip);
	}

	case ptbq_indirect:
		/* We're at an indirect jump or far transfer.
		 *
		 * We don't know the exact instruction class and there's no
		 * reason to decode the instruction for any other purpose.
		 *
		 * Indicate that we don't know the instruction class and leave
		 * it to our caller to decode the instruction if needed.
		 */
		block->iclass = ptic_error;

		/* This is neither a near call nor return so we don't need to
		 * touch the return-address stack.
		 *
		 * Just query the destination IP.
		 */
		status = pt_qry_indirect_branch(&decoder->query, &decoder->ip);
		if (status < 0)
			return status;

		/* Preserve the query decoder's response which indicates
		 * upcoming events.
		 */
		decoder->status = status;
		break;
	}

	return 0;
}

/* Proceed to the next decision point - try using the cache.
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
static int pt_blk_proceed_no_event_trycache(struct pt_block_decoder *decoder,
					    struct pt_block *block)
{
	struct pt_block_cache *bcache;
	struct pt_section *section;
	uint64_t laddr;
	int isid, errcode;

	if (!decoder || !block)
		return -pte_internal;

	isid = pt_blk_cached_section(&decoder->scache, &section, &laddr,
				     decoder->image, &decoder->asid,
				     decoder->ip);
	if (isid < 0) {
		if (isid != -pte_nomap)
			return isid;

		errcode = pt_blk_scache_invalidate(&decoder->scache);
		if (errcode < 0)
			return errcode;

		isid = pt_image_find(decoder->image, &section, &laddr,
				     &decoder->asid, decoder->ip);
		if (isid < 0) {
			if (isid != -pte_nomap)
				return isid;

			/* Even if there is no such section in the image, we may
			 * still read the memory via the callback function.
			 */
			return pt_blk_proceed_no_event_uncached(decoder, block);
		}

		errcode = pt_section_map(section);
		if (errcode < 0)
			goto out_put;

		errcode = pt_blk_cache_section(&decoder->scache, section, laddr,
					       isid);
		if (errcode < 0)
			goto out_unmap;
	}

	/* We do not switch sections inside a block. */
	if (isid != block->isid) {
		if (!pt_blk_block_is_empty(block))
			return 0;

		block->isid = isid;
	}

	bcache = pt_section_bcache(section);
	if (!bcache)
		return pt_blk_proceed_no_event_uncached(decoder, block);

	return pt_blk_proceed_no_event_cached(decoder, block, bcache, section,
					      laddr);

out_unmap:
	(void) pt_section_unmap(section);

out_put:
	(void) pt_section_put(section);
	return errcode;
}

/* Proceed to the next decision point.
 *
 * We don't have an event pending.  Ensure that tracing is enabled and proceed
 * as far as we get.  Try using the cache, if possible.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_proceed_no_event(struct pt_block_decoder *decoder,
				   struct pt_block *block)
{
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

	return pt_blk_proceed_no_event_trycache(decoder, block);
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
static int pt_blk_handle_erratum_bdm64(struct pt_block_decoder *decoder,
				       const struct pt_block *block,
				       const struct pt_event *ev)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	int status;

	if (!decoder || !block || !ev)
		return -pte_internal;

	/* This only affects aborts. */
	if (!ev->variant.tsx.aborted)
		return 0;

	/* This only affects branches that require trace.
	 *
	 * If the erratum hits, that branch ended the current block and brought
	 * us to the trailing event flow.
	 */
	if (pt_blk_block_is_empty(block))
		return 0;

	insn.mode = block->mode;
	insn.ip = block->end_ip;

	status = pt_insn_decode(&insn, &iext, decoder->image, &decoder->asid);
	if (status < 0)
		return 0;

	if (!pt_insn_is_branch(&insn, &iext))
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

/* Handle a trailing TSX event.
 *
 * This involves handling erratum BDM64.
 *
 * Returns a positive integer if the event is to be postponed.
 * Returns zero if the event was handled successfully.
 * Returns a negative error code otherwise.
 */
static inline int pt_blk_handle_trailing_tsx(struct pt_block_decoder *decoder,
					     struct pt_block *block,
					     const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	if (!ev->ip_suppressed) {
		if (decoder->query.config.errata.bdm64) {
			int status;

			status = pt_blk_handle_erratum_bdm64(decoder, block,
							     ev);
			if (status < 0)
				return 1;
		}

		if (decoder->ip != ev->variant.tsx.ip)
			return 1;
	}

	return pt_blk_apply_tsx(decoder, block, ev);
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
	if (!decoder)
		return -pte_internal;

	for (;;) {
		struct pt_event *ev;
		int status;

		status = pt_blk_fetch_event(decoder);
		if (status <= 0) {
			if (status < 0)
				return status;

			break;
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
				status = pt_blk_handle_erratum_skd022(decoder,
								      ev);
				if (status != 0) {
					if (status < 0)
						break;

					continue;
				}
			}


			status = pt_blk_apply_disabled(decoder, block, ev);
			if (status < 0)
				return status;

			continue;

		case ptev_async_branch:
			if (decoder->ip != ev->variant.async_branch.from)
				break;

			status = pt_blk_apply_async_branch(decoder, block, ev);
			if (status < 0)
				return status;

			continue;

		case ptev_async_paging:
			if (!ev->ip_suppressed &&
			    decoder->ip != ev->variant.async_paging.ip)
				break;

			status = pt_blk_apply_paging(decoder, block, ev);
			if (status < 0)
				return status;

			continue;

		case ptev_async_vmcs:
			if (!ev->ip_suppressed &&
			    decoder->ip != ev->variant.async_vmcs.ip)
				break;

			status = pt_blk_apply_vmcs(decoder, block, ev);
			if (status < 0)
				return status;

			continue;

		case ptev_exec_mode:
			if (!ev->ip_suppressed &&
			    decoder->ip != ev->variant.exec_mode.ip)
				break;

			status = pt_blk_apply_exec_mode(decoder, block, ev);
			if (status < 0)
				return status;

			continue;

		case ptev_tsx:
			status = pt_blk_handle_trailing_tsx(decoder, block, ev);
			if (status < 0)
				return status;

			if (status > 0)
				break;

			continue;

		case ptev_stop:
			status = pt_blk_apply_stop(decoder, block, ev);
			if (status < 0)
				return status;

			continue;
		}

		/* If we fall out of the switch, we're done. */
		break;
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
