/*
 * Copyright (c) 2016-2022, Intel Corporation
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
#include "pt_config.h"
#include "pt_asid.h"
#include "pt_compiler.h"

#include "intel-pt.h"

#include <string.h>
#include <stdlib.h>


static int pt_blk_proceed_trailing_event(struct pt_block_decoder *,
					 struct pt_block *);

static int pt_blk_fetch_event(struct pt_block_decoder *decoder)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	decoder->tsc = ev->tsc;
	decoder->has_tsc = ev->has_tsc;
	decoder->lost_mtc = ev->lost_mtc;
	decoder->lost_cyc = ev->lost_cyc;

	errcode = pt_evt_next(&decoder->evdec, ev, sizeof(*ev));
	if (errcode < 0) {
		decoder->status = errcode;
		memset(ev, 0xff, sizeof(*ev));
	}

	return 0;
}

static int pt_blk_status(const struct pt_block_decoder *decoder, int flags)
{
	if (!decoder)
		return -pte_internal;

	if (!decoder->enabled)
		flags |= pts_ip_suppressed;

	if (decoder->status == -pte_eos)
		flags |= pts_eos;

	return flags;
}

static void pt_blk_reset(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	decoder->tsc = 0ull;
	decoder->lost_mtc = 0u;
	decoder->lost_cyc = 0u;
	decoder->cbr = 0u;
	decoder->mode = ptem_unknown;
	decoder->ip = 0ull;
	decoder->status = -pte_nosync;
	decoder->enabled = 0;
	decoder->speculative = 0;
	decoder->has_tsc = 0;
	decoder->process_insn = 0;
	decoder->bound_paging = 0;
	decoder->bound_vmcs = 0;
	decoder->bound_ptwrite = 0;

	memset(&decoder->event, 0xff, sizeof(decoder->event));
	pt_retstack_init(&decoder->retstack);
	pt_asid_init(&decoder->asid);
}

/* Initialize the event decoder flags based on our flags. */

static int pt_blk_init_evt_flags(struct pt_conf_flags *qflags,
				 const struct pt_conf_flags *flags)
{
	if (!qflags || !flags)
		return -pte_internal;

	memset(qflags, 0, sizeof(*qflags));
	qflags->variant.event.keep_tcal_on_ovf =
		flags->variant.block.keep_tcal_on_ovf;

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

	/* Set the flags we need for the event decoder we use. */
	errcode = pt_blk_init_evt_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_decoder_init(&decoder->evdec, &config);
	if (errcode < 0)
		return errcode;

	pt_image_init(&decoder->default_image, NULL);
	decoder->image = &decoder->default_image;

	errcode = pt_msec_cache_init(&decoder->scache);
	if (errcode < 0)
		return errcode;

	pt_blk_reset(decoder);

	return 0;
}

void pt_blk_decoder_fini(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return;

	pt_msec_cache_fini(&decoder->scache);
	pt_image_fini(&decoder->default_image);
	pt_evt_decoder_fini(&decoder->evdec);
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

/* Synthesize a tick event or fetch the next event.
 *
 * We consumed a TIP or TNT event.  If the user asked for tick events, rewrite
 * the current event, otherwise fetch the next event.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_blk_tick(struct pt_block_decoder *decoder, uint64_t ip)
{
	if (!decoder)
		return -pte_internal;

	if (decoder->flags.variant.block.enable_tick_events) {
		struct pt_event *ev;

		ev = &decoder->event;
		if (ev->tsc != decoder->tsc) {
			ev->type = ptev_tick;
			ev->variant.tick.ip = ip;

			return 0;
		}
	}

	return pt_blk_fetch_event(decoder);
}

/* Handle an indirect branch.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_blk_proceed_indirect(struct pt_block_decoder *decoder)
{
	struct pt_event *ev;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_tip: {
		uint64_t ip;

		if (ev->ip_suppressed)
			return -pte_bad_packet;

		ip = decoder->ip;
		decoder->ip = ev->variant.tip.ip;

		return pt_blk_tick(decoder, ip);
	}

	case ptev_tnt: {
		struct pt_event_decoder evdec;
		struct pt_event tnt;
		int errcode;

		/* Deferred TIP may hide a TIP behind an in-progress TNT.
		 *
		 * We read ahead to get to the TIP and then re-install the
		 * in-progress TNT again.
		 *
		 * Back up the event decode state in case this isn't a deferred
		 * TIP after all.
		 */
		evdec = decoder->evdec;
		tnt = *ev;

		errcode = pt_evt_next(&decoder->evdec, ev, sizeof(*ev));
		if ((errcode < 0) || (ev->type != ptev_tip)) {
			decoder->evdec = evdec;
			*ev = tnt;

			return -pte_bad_query;
		}

		decoder->ip = ev->variant.tip.ip;

		/* We can't generate tick events for this TIP since we have to
		 * restore the in-progress TNT.
		 */
		*ev = tnt;

		return 0;
	}

	default:
		return -pte_bad_query;
	}
}

/* Handle a conditional branch.
 *
 * Returns a positive number if the branch was taken.
 * Returns zero if the branch was not taken.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_blk_cond_branch(struct pt_block_decoder *decoder)
{
	struct pt_event *ev;
	uint8_t size;

	if (!decoder)
		return -pte_internal;

	ev = &decoder->event;
	if (ev->type != ptev_tnt)
		return -pte_bad_query;

	size = ev->variant.tnt.size;
	if (!size)
		return -pte_internal;

	size -= 1;
	ev->variant.tnt.size = size;

	/* We postpone fetching the next event when size becomes zero to
	 * support tick events on one-bit TNT events.
	 */
	return (int) ((ev->variant.tnt.bits >> size) & 1);
}

static int pt_blk_start(struct pt_block_decoder *decoder)
{
	struct pt_event_decoder evdec;
	struct pt_event ev;
	int errcode;

	if (!decoder)
		return -pte_internal;

	/* We need to process satus update events from PSB+ in order to
	 * initialize our internal state and be able to diagnose
	 * inconsistencies during tracing.
	 *
	 * On the other hand, we need to provide those same status events to
	 * our user.  We do that by using a local copy of our event decoder, so
	 * when we're done, we rewind back to where we started.
	 */
	evdec = decoder->evdec;

	/* Process status update events from PSB+ to initialize our state. */
	for (;;) {
		/* Check that we're still processing the initial events.
		 *
		 * When the event decoder moves ahead, we're done with the
		 * initial PSB+.  We may get additional events from an adjacent
		 * PSB+, but we don't want to process them here.
		 */
		if (pt_evt_pos(&evdec) != pt_blk_pos(decoder))
			break;

		errcode = pt_evt_next(&evdec, &ev, sizeof(ev));
		if (errcode < 0) {
			if (errcode != -pte_eos)
				return errcode;

			break;
		}

		if (!ev.status_update)
			break;

		switch (ev.type) {
		case ptev_enabled:
			decoder->enabled = 1;
			decoder->ip = ev.variant.enabled.ip;
			break;

		default:
			continue;
		}

		break;
	}

	decoder->status = 0;

	errcode = pt_blk_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	return pt_blk_proceed_trailing_event(decoder, NULL);
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
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_blk_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_sync_forward(&decoder->evdec);
	if (errcode < 0)
		return errcode;

	return pt_blk_start(decoder);
}

int pt_blk_sync_backward(struct pt_block_decoder *decoder)
{
	const uint8_t *start, *sync, *pos;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	start = pt_blk_pos(decoder);
	if (!start) {
		const struct pt_config *config;

		config = pt_blk_config(decoder);
		if (!config)
			return -pte_internal;

		start = config->end;
		if (!start)
			return -pte_bad_config;
	}

	sync = start;
	for (;;) {
		errcode = pt_blk_sync_reset(decoder);
		if (errcode < 0)
			return errcode;

		do {
			errcode = pt_evt_sync_backward(&decoder->evdec);
			if (errcode < 0)
				return errcode;

			pos = pt_blk_pos(decoder);
		} while (sync <= pos);

		sync = pos;

		errcode = pt_blk_start(decoder);
		if (errcode < 0) {
			/* Ignore incomplete trace segments at the end.  We
			 * need a full PSB+ to start decoding.
			 */
			if (errcode != -pte_eos)
				return errcode;

			continue;
		}

		/* When starting inside or right after PSB+, we may end up at
		 * the same PSB again.  Skip it.
		 */
		pos = pt_blk_pos(decoder);
		if (pos < start)
			break;
	}

	return 0;
}

int pt_blk_sync_set(struct pt_block_decoder *decoder, uint64_t offset)
{
	int errcode;

	if (!decoder)
		return -pte_invalid;

	errcode = pt_blk_sync_reset(decoder);
	if (errcode < 0)
		return errcode;

	errcode = pt_evt_sync_set(&decoder->evdec, offset);
	if (errcode < 0)
		return errcode;

	return pt_blk_start(decoder);
}

int pt_blk_get_offset(const struct pt_block_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_evt_get_offset(&decoder->evdec, offset);
}

int pt_blk_get_sync_offset(const struct pt_block_decoder *decoder,
			   uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_evt_get_sync_offset(&decoder->evdec, offset);
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

	return pt_evt_get_config(&decoder->evdec);
}

int pt_blk_time(struct pt_block_decoder *decoder, uint64_t *time,
		uint32_t *lost_mtc, uint32_t *lost_cyc)
{
	if (!decoder || !time || !lost_mtc || !lost_cyc)
		return -pte_invalid;

	*time = decoder->tsc;
	*lost_mtc = decoder->lost_mtc;
	*lost_cyc = decoder->lost_cyc;

	return 0;
}

int pt_blk_core_bus_ratio(struct pt_block_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	*cbr = decoder->cbr;

	return 0;
}

int pt_blk_asid(const struct pt_block_decoder *decoder, struct pt_asid *asid,
		size_t size)
{
	if (!decoder || !asid)
		return -pte_invalid;

	return pt_asid_to_user(asid, &decoder->asid, size);
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

/* Proceed to the next IP using trace.
 *
 * We failed to proceed without trace.  This ends the current block.  Now use
 * trace to do one final step to determine the start IP of the next block.
 *
 * Does not update the return compression stack for indirect calls.  This is
 * expected to have been done, already, when trying to determine the next IP
 * without using trace.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 * Returns -pte_internal if @pip, @decoder, @insn, or @iext are NULL.
 * Returns -pte_internal if no trace is required.
 */
static int pt_blk_proceed_with_trace(struct pt_block_decoder *decoder,
				     const struct pt_insn *insn,
				     const struct pt_insn_ext *iext)
{
	if (!decoder || !insn || !iext)
		return -pte_internal;

	/* We handle non-taken conditional branches, and compressed returns
	 * directly in the switch.
	 *
	 * All kinds of branches are handled below the switch.
	 */
	switch (insn->iclass) {
	case ptic_cond_jump: {
		uint64_t ip;
		int tnt;

		ip = insn->ip + insn->size;

		tnt = pt_blk_cond_branch(decoder);
		if (tnt != 0) {
			if (tnt < 0)
				return tnt;

			ip += (uint64_t) (int64_t)
				iext->variant.branch.displacement;
		}

		decoder->ip = ip;

		return 0;
	}

	case ptic_return: {
		int tnt;

		/* Check for a compressed return.
		 *
		 * It is indicated by a taken conditional branch.
		 */
		tnt = pt_blk_cond_branch(decoder);
		if (tnt <= 0) {
			if (tnt == -pte_bad_query)
				break;

			if (!tnt)
				tnt = -pte_bad_retcomp;

			return tnt;
		}

		return pt_retstack_pop(&decoder->retstack, &decoder->ip);
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
	case ptic_indirect:
		break;

	case ptic_ptwrite:
	case ptic_other:
		return -pte_internal;

	case ptic_unknown:
		return -pte_bad_insn;
	}

	/* Process an indirect branch.
	 *
	 * This covers indirect jumps and calls, non-compressed returns, and all
	 * flavors of far transfers.
	 */
	return pt_blk_proceed_indirect(decoder);
}

/* Decode one instruction in a known section.
 *
 * Decode the instruction at @insn->ip in @msec assuming execution mode
 * @insn->mode.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_decode_in_section(struct pt_insn *insn,
				    struct pt_insn_ext *iext,
				    const struct pt_mapped_section *msec)
{
	int status;

	if (!insn || !iext)
		return -pte_internal;

	/* We know that @ip is contained in @section.
	 *
	 * Note that we need to translate @ip into a section offset.
	 */
	status = pt_msec_read(msec, insn->raw, sizeof(insn->raw), insn->ip);
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
		 * We only need to take care about direct near branches.
		 * Indirect and far branches require trace and will naturally
		 * end a block.
		 */
		if ((decoder->flags.variant.block.end_on_call &&
		     (insn->iclass == ptic_call)) ||
		    (decoder->flags.variant.block.end_on_jump &&
		     (insn->iclass == ptic_jump)))
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
		 * We only need to take care about direct near branches.
		 * Indirect and far branches require trace and will naturally
		 * end a block.
		 *
		 * The call at the end of the block may have reached @ip; make
		 * sure to indicate that.
		 */
		if ((decoder->flags.variant.block.end_on_call &&
		     (insn->iclass == ptic_call)) ||
		    (decoder->flags.variant.block.end_on_jump &&
		     (insn->iclass == ptic_jump))) {
			return (decoder->ip == ip ? 1 : 0);
		}
	}
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
	const struct pt_config *config;
	int status;

	if (!decoder || !block || !insn || !iext)
		return -pte_internal;

	config = pt_blk_config(decoder);
	if (!config)
		return -pte_internal;

	addr_filter = &config->addr_filter;
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
		 * We only need to take care about direct near branches.
		 * Indirect and far branches require trace and will naturally
		 * end a block.
		 */
		if ((decoder->flags.variant.block.end_on_call &&
		    (insn->iclass == ptic_call)) ||
		    (decoder->flags.variant.block.end_on_jump &&
		    (insn->iclass == ptic_jump)))
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
	if (!decoder || !block || !ev)
		return -pte_internal;

	if (ev->ip_suppressed) {
		const struct pt_config *config;

		config = pt_blk_config(decoder);
		if (!config)
			return -pte_internal;

		/* Due to SKL014 the TIP.PGD payload may be suppressed also for
		 * direct branches.
		 *
		 * If we don't have a filter configuration we assume that no
		 * address filters were used and the erratum does not apply.
		 *
		 * We might otherwise disable tracing too early.
		 */
		if (config->addr_filter.config.addr_cfg &&
		    config->errata.skl014)
			return pt_blk_proceed_skl014(decoder, block, insn,
						     iext);

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

/* Proceed to the event location for a ptwrite event.
 *
 * We have a ptwrite event pending.  Proceed to the event location and indicate
 * whether we were able to reach it.
 *
 * In case of the event binding to a ptwrite instruction, we pass beyond that
 * instruction and update the event to provide the instruction's IP.
 *
 * In the case of the event binding to an IP provided in the event, we move
 * beyond the instruction at that IP.
 *
 * Returns a positive integer if the event location was reached.
 * Returns zero if the event location was not reached.
 * Returns a negative error code otherwise.
 */
static int pt_blk_proceed_to_ptwrite(struct pt_block_decoder *decoder,
				     struct pt_block *block,
				     struct pt_insn *insn,
				     struct pt_insn_ext *iext,
				     struct pt_event *ev)
{
	int status;

	if (!insn || !ev)
		return -pte_internal;

	/* If we don't have an IP, the event binds to the next PTWRITE
	 * instruction.
	 *
	 * If we have an IP it still binds to the next PTWRITE instruction but
	 * now the IP tells us where that instruction is.  This makes most sense
	 * when tracing is disabled and we don't have any other means of finding
	 * the PTWRITE instruction.  We nevertheless distinguish the two cases,
	 * here.
	 *
	 * In both cases, we move beyond the PTWRITE instruction, so it will be
	 * the last instruction in the current block and @decoder->ip will point
	 * to the instruction following it.
	 */
	if (ev->ip_suppressed) {
		status = pt_blk_proceed_to_insn(decoder, block, insn, iext,
						pt_insn_is_ptwrite);
		if (status <= 0)
			return status;

		/* We now know the IP of the PTWRITE instruction corresponding
		 * to this event.  Fill it in to make it more convenient for the
		 * user to process the event.
		 */
		ev->variant.ptwrite.ip = insn->ip;
		ev->ip_suppressed = 0;
	} else {
		status = pt_blk_proceed_to_ip(decoder, block, insn, iext,
					      ev->variant.ptwrite.ip);
		if (status <= 0)
			return status;

		/* We reached the PTWRITE instruction and @decoder->ip points to
		 * it; @insn/@iext still contain the preceding instruction.
		 *
		 * Proceed beyond the PTWRITE to account for it.  Note that we
		 * may still overflow the block, which would cause us to
		 * postpone both instruction and event to the next block.
		 */
		status = pt_blk_proceed_one_insn(decoder, block, insn, iext);
		if (status <= 0)
			return status;
	}

	return 1;
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

/* Postpone proceeding past @insn/@iext and indicate a pending event.
 *
 * There may be further events pending on @insn/@iext.  Postpone proceeding past
 * @insn/@iext until we processed all events that bind to it.
 *
 * Returns a non-negative pt_status_flag bit-vector indicating a pending event
 * on success, a negative pt_error_code otherwise.
 */
static int pt_blk_postpone_insn(struct pt_block_decoder *decoder,
				const struct pt_insn *insn,
				const struct pt_insn_ext *iext)
{
	if (!decoder || !insn || !iext)
		return -pte_internal;

	/* Only one can be active. */
	if (decoder->process_insn)
		return -pte_internal;

	decoder->process_insn = 1;
	decoder->insn = *insn;
	decoder->iext = *iext;

	return pt_blk_status(decoder, pts_event_pending);
}

/* Remove any postponed instruction from @decoder.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_blk_clear_postponed_insn(struct pt_block_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	decoder->process_insn = 0;
	decoder->bound_paging = 0;
	decoder->bound_vmcs = 0;
	decoder->bound_ptwrite = 0;

	return 0;
}

/* Proceed past a postponed instruction.
 *
 * If an instruction has been postponed in @decoder, proceed past it.
 *
 * Returns zero on success, a negative pt_error_code otherwise.
 */
static int pt_blk_proceed_postponed_insn(struct pt_block_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_internal;

	/* There's nothing to do if we have no postponed instruction. */
	if (!decoder->process_insn)
		return 0;

	/* There's nothing to do if tracing got disabled. */
	if (!decoder->enabled)
		return pt_blk_clear_postponed_insn(decoder);

	status = pt_insn_next_ip(&decoder->ip, &decoder->insn, &decoder->iext);
	if (status < 0) {
		if (status != -pte_bad_query)
			return status;

		status = pt_blk_proceed_with_trace(decoder, &decoder->insn,
						   &decoder->iext);
		if (status < 0)
			return status;
	}

	return pt_blk_clear_postponed_insn(decoder);
}

/* Proceed to the next event.
 *
 * We have an event pending.  Proceed to the event location and indicate the
 * event to the user.
 *
 * On our way to the event location we may also be forced to postpone the event
 * to the next block, e.g. if we overflow the number of instructions in the
 * block or if we need trace in order to reach the event location.
 *
 * If we're not able to reach the event location, we return zero.  This is what
 * pt_blk_status() would return since:
 *
 *   - we suppress pts_eos as long as we're processing events
 *   - we do not set pts_ip_suppressed since tracing must be enabled
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_proceed_event(struct pt_block_decoder *decoder,
				struct pt_block *block)
{
	struct pt_insn_ext iext;
	struct pt_insn insn;
	struct pt_event *ev;
	int status;

	if (!decoder || !block)
		return -pte_internal;

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_enabled:
		break;

	case ptev_disabled:
		if (ev->status_update)
			break;

		status = pt_blk_proceed_to_disabled(decoder, block, &insn,
						    &iext, ev);
		if (status <= 0) {
			/* A synchronous disable event also binds to the next
			 * indirect or conditional branch, i.e. to any branch
			 * that would have required trace.
			 */
			if (status != -pte_bad_query)
				return status;

			status = pt_blk_set_disable_resume_ip(decoder, &insn);
			if (status < 0)
				return status;
		}

		break;

	case ptev_async_disabled: {
		const struct pt_config *config;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_disabled.at);
		if (status <= 0)
			return status;

		config = pt_blk_config(decoder);
		if (!config)
			return -pte_internal;

		if (config->errata.skd022) {
			status = pt_blk_handle_erratum_skd022(decoder, ev);
			if (status != 0) {
				if (status < 0)
					return status;

				/* If the erratum hits, we modify the event.
				 * Try again.
				 */
				return pt_blk_proceed_event(decoder, block);
			}
		}

		break;
	}

	case ptev_async_branch:
		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_branch.from);
		if (status <= 0)
			return status;

		break;

	case ptev_paging:
		if (!decoder->enabled)
			break;

		status = pt_blk_proceed_to_insn(decoder, block, &insn, &iext,
						pt_insn_binds_to_pip);
		if (status <= 0)
			return status;

		/* We bound a paging event.  Make sure we do not bind further
		 * paging events to this instruction.
		 */
		decoder->bound_paging = 1;

		return pt_blk_postpone_insn(decoder, &insn, &iext);

	case ptev_async_paging:
		if (ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_paging.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_vmcs:
		if (!decoder->enabled)
			break;

		status = pt_blk_proceed_to_insn(decoder, block, &insn, &iext,
						pt_insn_binds_to_vmcs);
		if (status <= 0)
			return status;

		/* We bound a vmcs event.  Make sure we do not bind further vmcs
		 * events to this instruction.
		 */
		decoder->bound_vmcs = 1;

		return pt_blk_postpone_insn(decoder, &insn, &iext);

	case ptev_async_vmcs:
		if (ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.async_vmcs.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_overflow:
		break;

	case ptev_exec_mode:
		if (ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.exec_mode.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_tsx:
		if (ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.tsx.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_stop:
		break;

	case ptev_exstop:
		if (!decoder->enabled || ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.exstop.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_mwait:
		if (!decoder->enabled || ev->ip_suppressed)
			break;

		status = pt_blk_proceed_to_ip(decoder, block, &insn, &iext,
					      ev->variant.mwait.ip);
		if (status <= 0)
			return status;

		break;

	case ptev_pwre:
	case ptev_pwrx:
		break;

	case ptev_ptwrite:
		if (!decoder->enabled)
			break;

		status = pt_blk_proceed_to_ptwrite(decoder, block, &insn,
						   &iext, ev);
		if (status <= 0)
			return status;

		/* We bound a ptwrite event.  Make sure we do not bind further
		 * ptwrite events to this instruction.
		 */
		decoder->bound_ptwrite = 1;

		return pt_blk_postpone_insn(decoder, &insn, &iext);

	case ptev_tick:
	case ptev_cbr:
	case ptev_mnt:
		break;

	case ptev_tip:
	case ptev_tnt:
		return -pte_internal;
	}

	return pt_blk_status(decoder, pts_event_pending);
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
static inline int pt_blk_is_in_section(const struct pt_mapped_section *msec,
				       uint64_t ip)
{
	uint64_t begin, end;

	begin = pt_msec_begin(msec);
	end = pt_msec_end(msec);

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

/* Insert a decode block cache entry.
 *
 * Add a decode block cache entry at @ioff.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static inline int pt_blk_add_decode(struct pt_block_cache *bcache,
				    uint64_t ioff, enum pt_exec_mode mode)
{
	struct pt_bcache_entry bce;

	memset(&bce, 0, sizeof(bce));
	bce.ninsn = 1;
	bce.mode = mode;
	bce.qualifier = ptbq_decode;

	return pt_bcache_add(bcache, ioff, bce);
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
static int
pt_blk_proceed_no_event_fill_cache(struct pt_block_decoder *decoder,
				   struct pt_block *block,
				   struct pt_block_cache *bcache,
				   const struct pt_mapped_section *msec,
				   size_t steps)
{
	struct pt_bcache_entry bce;
	struct pt_insn_ext iext;
	struct pt_insn insn;
	uint64_t nip, dip, ioff, noff;
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

	ioff = pt_msec_unmap(msec, insn.ip);

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
		case ptic_ptwrite:
		case ptic_unknown:
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
		case ptic_indirect:
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

		status = pt_bcache_add(bcache, ioff, bce);
		if (status < 0)
			return status;

		return pt_blk_proceed_with_trace(decoder, &insn, &iext);
	}

	/* The next instruction's IP. */
	nip = decoder->ip;
	noff = pt_msec_unmap(msec, nip);

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
	 *   - at near direct backwards jumps to detect section splits
	 *
	 *     In case the current section is split underneath us, we must take
	 *     care to detect that split.
	 *
	 *     There is one corner case where the split is in the middle of a
	 *     linear sequence of instructions that branches back into the
	 *     originating section.
	 *
	 *     Calls, indirect branches, and far branches are already covered
	 *     since they either require trace or already require us to stop
	 *     (i.e. near direct calls) for other reasons.  That leaves near
	 *     direct backward jumps.
	 *
	 *     Instead of the decode stop at the jump instruction we're using we
	 *     could have made sure that other block cache entries that extend
	 *     this one insert a trampoline to the jump's entry.  This would
	 *     have been a bit more complicated.
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
	switch (insn.iclass) {
	case ptic_call:
		return pt_blk_add_decode(bcache, ioff, insn.mode);

	case ptic_jump:
		/* An indirect branch requires trace and should have been
		 * handled above.
		 */
		if (!iext.variant.branch.is_direct)
			return -pte_internal;

		if (iext.variant.branch.displacement < 0 ||
		    decoder->flags.variant.block.end_on_jump)
			return pt_blk_add_decode(bcache, ioff, insn.mode);

		fallthrough;
	default:
		if (!pt_blk_is_in_section(msec, nip) || block->truncated)
			return pt_blk_add_decode(bcache, ioff, insn.mode);

		break;
	}

	/* We proceeded one instruction.  Let's see if we have a cache entry for
	 * the next instruction.
	 */
	status = pt_bcache_lookup(&bce, bcache, noff);
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
			return pt_blk_add_trampoline(bcache, ioff, noff,
						     insn.mode);

		status = pt_blk_proceed_no_event_fill_cache(decoder, block,
							    bcache, msec,
							    steps);
		if (status < 0)
			return status;

		/* Let's see if we have more luck this time. */
		status = pt_bcache_lookup(&bce, bcache, noff);
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
	dip = nip + (uint64_t) (int64_t) bce.displacement;
	disp = (int64_t) (dip - insn.ip);

	/* We may have switched sections if the section was split.  See
	 * pt_blk_proceed_no_event_cached() for a more elaborate comment.
	 *
	 * We're not adding a block cache entry since this won't apply to the
	 * original section which may be shared with other decoders.
	 *
	 * We will instead take the slow path until the end of the section.
	 */
	if (!pt_blk_is_in_section(msec, dip))
		return 0;

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
		return pt_blk_add_trampoline(bcache, ioff, noff, insn.mode);

	/* We're done.  Add the cache entry.
	 *
	 * There's a chance that other decoders updated the cache entry in the
	 * meantime.  They should have come to the same conclusion as we,
	 * though, and the cache entries should be identical.
	 *
	 * Cache updates are atomic so even if the two versions were not
	 * identical, we wouldn't care because they are both correct.
	 */
	return pt_bcache_add(bcache, ioff, bce);
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
 * @block's isid.  All reads are done within @msec as we're not switching
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
					  const struct pt_mapped_section *msec)
{
	struct pt_bcache_entry bce;
	uint16_t binsn, ninsn;
	uint64_t offset, nip;
	int status;

	if (!decoder || !block)
		return -pte_internal;

	offset = pt_msec_unmap(msec, decoder->ip);
	status = pt_bcache_lookup(&bce, bcache, offset);
	if (status < 0)
		return status;

	/* If we don't find a valid cache entry, fill the cache. */
	if (!pt_bce_is_valid(bce))
		return pt_blk_proceed_no_event_fill_cache(decoder, block,
							  bcache, msec,
							  bcache_fill_steps);

	/* If we switched sections, the origianl section must have been split
	 * underneath us.  A split preserves the block cache of the original
	 * section.
	 *
	 * Crossing sections requires ending the block so we can indicate the
	 * proper isid for the entire block.
	 *
	 * Plus there's the chance that the new section that caused the original
	 * section to split changed instructions.
	 *
	 * This check will also cover changes to a linear sequence of code we
	 * would otherwise have jumped over as long as the start and end are in
	 * different sub-sections.
	 *
	 * Since we stop on every (backwards) branch (through an artificial stop
	 * in the case of a near direct backward branch) we will detect all
	 * section splits.
	 *
	 * Switch to the slow path until we reach the end of this section.
	 */
	nip = decoder->ip + (uint64_t) (int64_t) bce.displacement;
	if (!pt_blk_is_in_section(msec, nip))
		return pt_blk_proceed_no_event_uncached(decoder, block);

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
	decoder->ip = nip;

	/* We don't know the instruction class so we should be setting it to
	 * ptic_unknown.  Since we will be able to fill it back in later in
	 * most cases, we move the clearing to the switch cases that don't.
	 */
	block->end_ip = nip;
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
		block->iclass = ptic_unknown;

		return pt_blk_proceed_no_event_cached(decoder, block, bcache,
						      msec);

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
			int tnt;

			/* If the branch is not taken, we don't need to decode
			 * the instruction at @decoder->ip.
			 *
			 * If it is taken, we have to implement everything here.
			 * We can't use the normal decode and proceed-with-trace
			 * flow since we already consumed the TNT bit.
			 */
			ip = decoder->ip;
			tnt = pt_blk_cond_branch(decoder);
			if (tnt != 0) {
				struct pt_insn_ext iext;
				struct pt_insn insn;

				if (tnt < 0)
					return tnt;

				memset(&iext, 0, sizeof(iext));
				memset(&insn, 0, sizeof(insn));

				insn.mode = pt_bce_exec_mode(bce);
				insn.ip = ip;

				status = pt_blk_decode_in_section(&insn, &iext,
								  msec);
				if (status < 0)
					return status;

				ip += (uint64_t) (int64_t)
					iext.variant.branch.displacement;
			}

			decoder->ip = ip + bce.isize;

			return 0;
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

		status = pt_blk_decode_in_section(&insn, &iext, msec);
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
		 * We only need to take care about direct near branches.
		 * Indirect and far branches require trace and will naturally
		 * end a block.
		 */
		if ((decoder->flags.variant.block.end_on_call &&
		     (insn.iclass == ptic_call)) ||
		    (decoder->flags.variant.block.end_on_jump &&
		     (insn.iclass == ptic_jump)))
			return 0;

		/* If we can proceed without trace and we stay in @msec we may
		 * proceed further.
		 *
		 * We're done if we switch sections, though.
		 */
		if (!pt_blk_is_in_section(msec, decoder->ip))
			return 0;

		return pt_blk_proceed_no_event_cached(decoder, block, bcache,
						      msec);
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

			status = pt_blk_decode_in_section(&insn, &iext, msec);
			if (status < 0)
				return status;

			ip += insn.size;
		}

		status = pt_retstack_push(&decoder->retstack, ip);
		if (status < 0)
			return status;

		return pt_blk_proceed_indirect(decoder);
	}

	case ptbq_return: {
		int tnt;

		/* We're at a near return. */
		block->iclass = ptic_return;

		/* Check for a compressed return.
		 *
		 * It is indicated by a taken conditional branch.
		 */
		tnt = pt_blk_cond_branch(decoder);
		if (tnt <= 0) {
			/* If we do not have a TNT bit, the return is not
			 * compressed.
			 *
			 * We need another query to determine the destination.
			 */
			if (tnt == -pte_bad_query)
				return pt_blk_proceed_indirect(decoder);

			if (!tnt)
				tnt = -pte_bad_retcomp;

			return tnt;
		}

		return pt_retstack_pop(&decoder->retstack, &decoder->ip);
	}

	case ptbq_indirect:
		/* We're at an indirect jump or far transfer.
		 *
		 * We don't know the exact instruction class and there's no
		 * reason to decode the instruction for any other purpose.
		 *
		 * Leave it to our caller to decode the instruction if needed.
		 */
		block->iclass = ptic_indirect;

		/* This is neither a near call nor return so we don't need to
		 * touch the return-address stack.
		 *
		 * Just query the destination IP.
		 */
		return pt_blk_proceed_indirect(decoder);
	}

	return -pte_internal;
}

static int pt_blk_msec_fill(struct pt_block_decoder *decoder,
			    const struct pt_mapped_section **pmsec)
{
	const struct pt_mapped_section *msec;
	struct pt_section *section;
	int isid, errcode;

	if (!decoder || !pmsec)
		return -pte_internal;

	isid = pt_msec_cache_fill(&decoder->scache, &msec,  decoder->image,
				  &decoder->asid, decoder->ip);
	if (isid < 0)
		return isid;

	section = pt_msec_section(msec);
	if (!section)
		return -pte_internal;

	*pmsec = msec;

	errcode = pt_section_request_bcache(section);
	if (errcode < 0)
		return errcode;

	return isid;
}

static inline int pt_blk_msec_lookup(struct pt_block_decoder *decoder,
				     const struct pt_mapped_section **pmsec)
{
	int isid;

	if (!decoder)
		return -pte_internal;

	isid = pt_msec_cache_read(&decoder->scache, pmsec, decoder->image,
				  decoder->ip);
	if (isid < 0) {
		if (isid != -pte_nomap)
			return isid;

		return pt_blk_msec_fill(decoder, pmsec);
	}

	return isid;
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
static int pt_blk_proceed_no_event(struct pt_block_decoder *decoder,
				   struct pt_block *block)
{
	const struct pt_mapped_section *msec;
	struct pt_block_cache *bcache;
	struct pt_section *section;
	int isid;

	if (!decoder || !block)
		return -pte_internal;

	isid = pt_blk_msec_lookup(decoder, &msec);
	if (isid < 0) {
		if (isid != -pte_nomap)
			return isid;

		/* Even if there is no such section in the image, we may still
		 * read the memory via the callback function.
		 */
		return pt_blk_proceed_no_event_uncached(decoder, block);
	}

	/* We do not switch sections inside a block. */
	if (isid != block->isid) {
		if (!pt_blk_block_is_empty(block))
			return 0;

		block->isid = isid;
	}

	section = pt_msec_section(msec);
	if (!section)
		return -pte_internal;

	bcache = pt_section_bcache(section);
	if (!bcache)
		return pt_blk_proceed_no_event_uncached(decoder, block);

	return pt_blk_proceed_no_event_cached(decoder, block, bcache, msec);
}

/* Proceed to the next event or decision point.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_proceed(struct pt_block_decoder *decoder,
			  struct pt_block *block)
{
	const struct pt_event *ev;
	int status;

	if (!decoder)
		return -pte_internal;

	/* Report deferred event decode errors. */
	status = decoder->status;
	if (status < 0) {
		if (status != -pte_eos)
			return status;

		/* If we ran out of trace, we still allow the user to proceed
		 * until we actually need trace.  We indicate the upcoming end
		 * of the trace on each pt_blk_next() or pt_blk_event() call.
		 *
		 * This allows the user to stitch traces from adjacent PSB
		 * segments together.
		 *
		 * We do need tracing to be enabled, though.
		 */
		if (!decoder->enabled)
			return -pte_eos;

		status = pt_blk_proceed_no_event(decoder, block);
		if (status < 0)
			return status;

		return pts_eos;
	}

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_tnt:
	case ptev_tip:
		/* Tracing must be enabled.
		 *
		 * If we ran out of trace we should have taken the above route.
		 */
		if (!decoder->enabled)
			return -pte_no_enable;

		status = pt_blk_proceed_no_event(decoder, block);
		if (status < 0)
			return status;

		return pt_blk_proceed_trailing_event(decoder, block);

	default:
		return pt_blk_proceed_event(decoder, block);
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
		return status;

	/* We can't reach the event location.  This could either mean that we
	 * stopped too early (and status is zero) or that the erratum hit.
	 *
	 * We assume the latter and pretend that the previous branch brought us
	 * to the event location, instead.
	 */
	decoder->ip = ev->variant.tsx.ip;

	return 1;
}

/* Check whether a trailing TSX event should be postponed.
 *
 * This involves handling erratum BDM64.
 *
 * Returns a positive integer if the event is to be postponed.
 * Returns zero if the event should be processed.
 * Returns a negative error code otherwise.
 */
static inline int pt_blk_postpone_trailing_tsx(struct pt_block_decoder *decoder,
					       struct pt_block *block,
					       const struct pt_event *ev)
{
	int status;

	if (!decoder || !ev)
		return -pte_internal;

	if (ev->ip_suppressed)
		return 0;

	if (block) {
		const struct pt_config *config;

		config = pt_blk_config(decoder);
		if (!config)
			return -pte_internal;

		if (config->errata.bdm64) {
			status = pt_blk_handle_erratum_bdm64(decoder, block,
							     ev);
			if (status < 0)
				return 1;
		}
	}

	if (decoder->ip != ev->variant.tsx.ip)
		return 1;

	return 0;
}

/* Proceed with events that bind to the current decoder IP.
 *
 * This function is used in the following scenarios:
 *
 *   - we just synchronized onto the trace stream
 *   - we ended a block and proceeded to the next IP
 *   - we processed an event that was indicated by this function
 *
 * Check if there is an event at the current IP that needs to be indicated to
 * the user.
 *
 * Returns a non-negative pt_status_flag bit-vector on success, a negative error
 * code otherwise.
 */
static int pt_blk_proceed_trailing_event(struct pt_block_decoder *decoder,
					 struct pt_block *block)
{
	struct pt_event *ev;
	int status;

	if (!decoder)
		return -pte_internal;

	/* Check if there is an event to process. */
	status = decoder->status;
	if (status < 0) {
		/* Proceed past any postponed instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, 0);
	}

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_tnt:
		/* Synthesize a tick event on the first used TNT bit.
		 *
		 * We do not actually need to track whether this is the first
		 * or any other bit in the current TNT event.  On the second
		 * bit, the decoder's TSC will already match the event's.
		 *
		 * This also covers TNT events that did not get their own
		 * timestamp, e.g. due to non-zero CYC threshold.  They will
		 * not receive a separate tick event.
		 */

		/* We only generate tick events on request, during normal
		 * processing, and only once.
		 */
		if (!decoder->flags.variant.block.enable_tick_events ||
		    !block ||
		    (!ev->has_tsc || (ev->tsc == decoder->tsc))) {
			/* We're done if this TNT event is still in use. */
			if (ev->variant.tnt.size)
				break;

			/* We postponed fetching the next event when we used up
			 * all the TNT bits to also cover 1-bit TNT events.
			 *
			 * Fetch it now that we decided to not generate a tick
			 * event.
			 */
			status = pt_blk_fetch_event(decoder);
			if (status < 0)
				return status;

			/* This may expose new trailing events. */
			return pt_blk_proceed_trailing_event(decoder, block);
		}

		/* Postpone the tick event if we had to break the block. */
		if ((block->iclass != ptic_cond_jump) &&
		    (block->iclass != ptic_return))
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_tip:
		break;

	case ptev_tick:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_disabled:
		/* Synchronous disable events are normally indicated on the
		 * event flow.
		 */
		if (!decoder->process_insn)
			break;

		/* A sync disable may bind to a CR3 changing instruction. */
		if (ev->ip_suppressed &&
		    pt_insn_changes_cr3(&decoder->insn, &decoder->iext))
			return pt_blk_status(decoder, pts_event_pending);

		/* Or it binds to the next branch that would require trace.
		 *
		 * Try to complete processing the current instruction by
		 * proceeding past it.  If that fails because it would require
		 * trace, we can apply the disabled event.
		 */
		status = pt_insn_next_ip(&decoder->ip, &decoder->insn,
					 &decoder->iext);
		if (status < 0) {
			if (status != -pte_bad_query)
				return status;

			status = pt_blk_set_disable_resume_ip(decoder,
							      &decoder->insn);
			if (status < 0)
				return status;

			return pt_blk_status(decoder, pts_event_pending);
		}

		/* We proceeded past the current instruction. */
		status = pt_blk_clear_postponed_insn(decoder);
		if (status < 0)
			return status;

		/* This might have brought us to the disable IP. */
		if (!ev->ip_suppressed &&
		    decoder->ip == ev->variant.disabled.ip)
			return pt_blk_status(decoder, pts_event_pending);

		break;

	case ptev_enabled:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_async_disabled: {
		const struct pt_config *config;

		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (decoder->ip != ev->variant.async_disabled.at)
			break;

		config = pt_blk_config(decoder);
		if (!config)
			return -pte_internal;

		if (config->errata.skd022) {
			status = pt_blk_handle_erratum_skd022(decoder, ev);
			if (status != 0) {
				if (status < 0)
					return status;

				/* If the erratum applies, the event is modified
				 * to a synchronous disable event that will be
				 * processed on the next pt_blk_proceed_event()
				 * call.  We're done.
				 */
				break;
			}
		}

		return pt_blk_status(decoder, pts_event_pending);
	}

	case ptev_async_branch:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (decoder->ip != ev->variant.async_branch.from)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_paging:
		/* We apply the event immediately if we're not tracing. */
		if (!decoder->enabled)
			return pt_blk_status(decoder, pts_event_pending);

		/* Synchronous paging events are normally indicated on the event
		 * flow, unless they bind to the same instruction as a previous
		 * event.
		 *
		 * We bind at most one paging event to an instruction, though.
		 */
		if (!decoder->process_insn || decoder->bound_paging)
			break;

		/* We're done if we're not binding to the currently postponed
		 * instruction.  We will process the event on the normal event
		 * flow in the next iteration.
		 */
		if (!pt_insn_binds_to_pip(&decoder->insn, &decoder->iext))
			break;

		/* We bound a paging event.  Make sure we do not bind further
		 * paging events to this instruction.
		 */
		decoder->bound_paging = 1;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_async_paging:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_paging.ip)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_vmcs:
		/* We apply the event immediately if we're not tracing. */
		if (!decoder->enabled)
			return pt_blk_status(decoder, pts_event_pending);

		/* Synchronous vmcs events are normally indicated on the event
		 * flow, unless they bind to the same instruction as a previous
		 * event.
		 *
		 * We bind at most one vmcs event to an instruction, though.
		 */
		if (!decoder->process_insn || decoder->bound_vmcs)
			break;

		/* We're done if we're not binding to the currently postponed
		 * instruction.  We will process the event on the normal event
		 * flow in the next iteration.
		 */
		if (!pt_insn_binds_to_vmcs(&decoder->insn, &decoder->iext))
			break;

		/* We bound a vmcs event.  Make sure we do not bind further vmcs
		 * events to this instruction.
		 */
		decoder->bound_vmcs = 1;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_async_vmcs:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_vmcs.ip)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_overflow:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_exec_mode:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.exec_mode.ip)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_tsx:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		status = pt_blk_postpone_trailing_tsx(decoder, block, ev);
		if (status != 0) {
			if (status < 0)
				return status;

			break;
		}

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_stop:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_exstop:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (!ev->ip_suppressed && decoder->enabled &&
		    decoder->ip != ev->variant.exstop.ip)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_mwait:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		if (!ev->ip_suppressed && decoder->enabled &&
		    decoder->ip != ev->variant.mwait.ip)
			break;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_pwre:
	case ptev_pwrx:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_ptwrite:
		/* We apply the event immediately if we're not tracing. */
		if (!decoder->enabled)
			return pt_blk_status(decoder, pts_event_pending);

		/* Ptwrite events are normally indicated on the event flow,
		 * unless they bind to the same instruction as a previous event.
		 *
		 * We bind at most one ptwrite event to an instruction, though.
		 */
		if (!decoder->process_insn || decoder->bound_ptwrite)
			break;

		/* We're done if we're not binding to the currently postponed
		 * instruction.  We will process the event on the normal event
		 * flow in the next iteration.
		 */
		if (!ev->ip_suppressed ||
		    !pt_insn_is_ptwrite(&decoder->insn, &decoder->iext))
			break;

		/* We bound a ptwrite event.  Make sure we do not bind further
		 * ptwrite events to this instruction.
		 */
		decoder->bound_ptwrite = 1;

		return pt_blk_status(decoder, pts_event_pending);

	case ptev_cbr:
	case ptev_mnt:
		/* This event does not bind to an instruction. */
		status = pt_blk_proceed_postponed_insn(decoder);
		if (status < 0)
			return status;

		return pt_blk_status(decoder, pts_event_pending);
	}

	/* No further events.  Proceed past any postponed instruction. */
	status = pt_blk_proceed_postponed_insn(decoder);
	if (status < 0)
		return status;

	return pt_blk_status(decoder, 0);
}

int pt_blk_next(struct pt_block_decoder *decoder, struct pt_block *ublock,
		size_t size)
{
	struct pt_block block, *pblock;
	int errcode, status;

	if (!decoder || !ublock)
		return -pte_invalid;

	pblock = size == sizeof(block) ? ublock : &block;

	/* Zero-initialize the block in case of error returns. */
	memset(pblock, 0, sizeof(*pblock));

	/* Fill in a few things from the current decode state.
	 *
	 * This reflects the state of the last pt_blk_next() or pt_blk_start()
	 * call.  Note that, unless we stop with tracing disabled, we proceed
	 * already to the start IP of the next block.
	 *
	 * Some of the state may later be overwritten as we process events.
	 */
	pblock->ip = decoder->ip;
	pblock->mode = decoder->mode;
	if (decoder->speculative)
		pblock->speculative = 1;

	/* Proceed one block. */
	status = pt_blk_proceed(decoder, pblock);

	errcode = block_to_user(ublock, size, pblock);
	if (errcode < 0)
		return errcode;

	return status;
}

/* Process an enabled event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_enabled(struct pt_block_decoder *decoder,
				  const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* Use status update events to diagnose inconsistencies. */
	if (ev->status_update) {
		if (!decoder->enabled)
			return -pte_bad_status_update;

		return 0;
	}

	/* We must have an IP in order to start decoding. */
	if (ev->ip_suppressed)
		return -pte_noip;

	/* We must currently be disabled. */
	if (decoder->enabled)
		return -pte_bad_context;

	decoder->ip = ev->variant.enabled.ip;
	decoder->enabled = 1;

	return 0;
}

/* Process a disabled event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_disabled(struct pt_block_decoder *decoder,
				   const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* Use status update events to diagnose inconsistencies. */
	if (ev->status_update) {
		if (decoder->enabled)
			return -pte_bad_status_update;

		return 0;
	}

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	/* We preserve @decoder->ip.  This is where we expect tracing to resume
	 * and we'll indicate that on the subsequent enabled event if tracing
	 * actually does resume from there.
	 */
	decoder->enabled = 0;

	return 0;
}

/* Process an asynchronous branch event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_async_branch(struct pt_block_decoder *decoder,
				       const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* We must currently be enabled. */
	if (!decoder->enabled)
		return -pte_bad_context;

	/* Jump to the branch destination.  We will continue from there in the
	 * next iteration.
	 */
	decoder->ip = ev->variant.async_branch.to;

	return 0;
}

/* Process a paging event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_paging(struct pt_block_decoder *decoder,
				 const struct pt_event *ev)
{
	uint64_t cr3;
	int errcode;

	if (!decoder || !ev)
		return -pte_internal;

	cr3 = ev->variant.paging.cr3;
	if (decoder->asid.cr3 != cr3) {
		errcode = pt_msec_cache_invalidate(&decoder->scache);
		if (errcode < 0)
			return errcode;

		decoder->asid.cr3 = cr3;
	}

	return 0;
}

/* Process a vmcs event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_vmcs(struct pt_block_decoder *decoder,
			       const struct pt_event *ev)
{
	uint64_t vmcs;
	int errcode;

	if (!decoder || !ev)
		return -pte_internal;

	vmcs = ev->variant.vmcs.base;
	if (decoder->asid.vmcs != vmcs) {
		errcode = pt_msec_cache_invalidate(&decoder->scache);
		if (errcode < 0)
			return errcode;

		decoder->asid.vmcs = vmcs;
	}

	return 0;
}

/* Process an overflow event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_overflow(struct pt_block_decoder *decoder,
				   const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

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
	} else {
		/* Tracing is enabled and we're at the IP at which the overflow
		 * resolved.
		 */
		decoder->enabled = 1;
		decoder->ip = ev->variant.overflow.ip;
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

/* Process an exec mode event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_exec_mode(struct pt_block_decoder *decoder,
				    const struct pt_event *ev)
{
	enum pt_exec_mode mode;

	if (!decoder || !ev)
		return -pte_internal;

	/* Use status update events to diagnose inconsistencies. */
	mode = ev->variant.exec_mode.mode;
	if (ev->status_update && decoder->enabled &&
	    decoder->mode != ptem_unknown && decoder->mode != mode)
		return -pte_bad_status_update;

	decoder->mode = mode;

	return 0;
}

/* Process a tsx event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_tsx(struct pt_block_decoder *decoder,
			      const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	decoder->speculative = ev->variant.tsx.speculative;

	return 0;
}

/* Process a stop event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_stop(struct pt_block_decoder *decoder,
			       const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	/* This event can't be a status update. */
	if (ev->status_update)
		return -pte_bad_context;

	/* Tracing is always disabled before it is stopped. */
	if (decoder->enabled)
		return -pte_bad_context;

	return 0;
}

/* Process a cbr event.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_blk_process_cbr(struct pt_block_decoder *decoder,
			      const struct pt_event *ev)
{
	if (!decoder || !ev)
		return -pte_internal;

	decoder->cbr = ev->variant.cbr.ratio;

	return 0;
}

int pt_blk_event(struct pt_block_decoder *decoder, struct pt_event *uevent,
		 size_t size)
{
	struct pt_event *ev;
	int errcode;

	if (!decoder || !uevent)
		return -pte_invalid;

	/* Report any deferred event decode errors. */
	errcode = decoder->status;
	if (errcode < 0)
		return errcode;

	/* Make sure we're not writing beyond the memory provided by the user.
	 *
	 * We might truncate details of an event but only for those events the
	 * user can't know about, anyway.
	 */
	if (sizeof(*ev) < size)
		size = sizeof(*ev);

	ev = &decoder->event;
	switch (ev->type) {
	case ptev_tnt: {
		/* Synthesize a tick event on the first used TNT bit. */
		struct pt_event tick;

		if (!decoder->flags.variant.block.enable_tick_events)
			return -pte_bad_query;

		if (!ev->has_tsc || (ev->tsc == decoder->tsc))
			return -pte_bad_query;

		memset(&tick, 0, sizeof(tick));
		tick.type = ptev_tick;
		tick.has_tsc = 1;
		tick.tsc = ev->tsc;
		tick.lost_mtc = ev->lost_mtc;
		tick.lost_cyc = ev->lost_cyc;
		tick.variant.tick.ip = decoder->ip;

		/* We normally update the decoder's TSC when fetching the next
		 * event.  In this case, however, we use the timestamp to
		 * ensure we send at most one tick event per TNT.  Unlike other
		 * events, the TNT event remains active.
		 */
		decoder->has_tsc = 1;
		decoder->tsc = tick.tsc;
		decoder->lost_mtc = tick.lost_mtc;
		decoder->lost_cyc = tick.lost_cyc;

		/* Copy the event to the user. */
		memcpy(uevent, &tick, size);

		/* Only fetch the  next event if we used up all TNT bits. */
		if (!ev->variant.tnt.size) {
			errcode = pt_blk_fetch_event(decoder);
			if (errcode < 0)
				return errcode;
		}

		/* Indicate further events. */
		return pt_blk_proceed_trailing_event(decoder, NULL);
	}

	case ptev_enabled:
		/* Indicate that tracing resumes from the IP at which tracing
		 * had been disabled before (with some special treatment for
		 * calls).
		 */
		if (ev->variant.enabled.ip == decoder->ip)
			ev->variant.enabled.resumed = 1;

		errcode = pt_blk_process_enabled(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_async_disabled:
		if (decoder->ip != ev->variant.async_disabled.at)
			return -pte_bad_query;

		fallthrough;
	case ptev_disabled:

		errcode = pt_blk_process_disabled(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_async_branch:
		if (decoder->ip != ev->variant.async_branch.from)
			return -pte_bad_query;

		errcode = pt_blk_process_async_branch(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_async_paging:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_paging.ip)
			return -pte_bad_query;

		fallthrough;
	case ptev_paging:
		errcode = pt_blk_process_paging(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_async_vmcs:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.async_vmcs.ip)
			return -pte_bad_query;

		fallthrough;
	case ptev_vmcs:
		errcode = pt_blk_process_vmcs(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_overflow:
		errcode = pt_blk_process_overflow(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_exec_mode:
		if (!ev->ip_suppressed &&
		    decoder->ip != ev->variant.exec_mode.ip)
			return -pte_bad_query;

		errcode = pt_blk_process_exec_mode(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_tsx:
		if (!ev->ip_suppressed && decoder->ip != ev->variant.tsx.ip)
			return -pte_bad_query;

		errcode = pt_blk_process_tsx(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_stop:
		errcode = pt_blk_process_stop(decoder, ev);
		if (errcode < 0)
			return errcode;

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
	case ptev_tick:
	case ptev_mnt:
		break;

	case ptev_cbr:
		errcode = pt_blk_process_cbr(decoder, ev);
		if (errcode < 0)
			return errcode;

		break;

	case ptev_tip:
		return -pte_bad_query;
	}

	/* Copy the event to the user. */
	memcpy(uevent, ev, size);

	/* Fetch the next event. */
	errcode = pt_blk_fetch_event(decoder);
	if (errcode < 0)
		return errcode;

	/* Indicate further events. */
	return pt_blk_proceed_trailing_event(decoder, NULL);
}
