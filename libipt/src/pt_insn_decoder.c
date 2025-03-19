/*
 * Copyright (C) 2013-2025 Intel Corporation
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

#include "pt_insn_decoder.h"
#include "pt_config.h"

#include "intel-pt.h"

#include <string.h>
#include <stdlib.h>


static void pt_insn_reset(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return;

	memset(&decoder->block, 0, sizeof(decoder->block));

	decoder->status = 0;
}

/* Initialize the block decoder flags based on our flags. */

static int pt_insn_init_blk_flags(struct pt_conf_flags *bflags,
				  const struct pt_conf_flags *flags)
{
	if (!bflags || !flags)
		return -pte_internal;

	memset(bflags, 0, sizeof(*bflags));
	bflags->variant.block.enable_tick_events =
		flags->variant.insn.enable_tick_events;
	bflags->variant.block.keep_tcal_on_ovf =
		flags->variant.insn.keep_tcal_on_ovf;
	bflags->variant.block.enable_iflags_events =
		flags->variant.insn.enable_iflags_events;

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

	/* Set the flags we need for the block decoder we use. */
	errcode = pt_insn_init_blk_flags(&config.flags, &decoder->flags);
	if (errcode < 0)
		return errcode;

	pt_insn_reset(decoder);

	return pt_blk_decoder_init(&decoder->blkdec, &config);
}

void pt_insn_decoder_fini(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return;

	pt_blk_decoder_fini(&decoder->blkdec);
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

int pt_insn_sync_forward(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_blk_sync_forward(&decoder->blkdec);
	if (status < 0)
		return status;

	decoder->status = status;
	return status;
}

int pt_insn_sync_backward(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_blk_sync_backward(&decoder->blkdec);
	if (status < 0)
		return status;

	decoder->status = status;
	return status;
}

int pt_insn_sync_set(struct pt_insn_decoder *decoder, uint64_t offset)
{
	int status;

	if (!decoder)
		return -pte_invalid;

	pt_insn_reset(decoder);

	status = pt_blk_sync_set(&decoder->blkdec, offset);
	if (status < 0)
		return status;

	decoder->status = status;
	return status;
}

int pt_insn_resync(struct pt_insn_decoder *decoder)
{
	int status;

	if (!decoder)
		return -pte_internal;

	pt_insn_reset(decoder);

	status = pt_blk_resync(&decoder->blkdec);
	if (status < 0)
		return status;

	decoder->status = status;

	return status;
}

int pt_insn_get_offset(const struct pt_insn_decoder *decoder, uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_blk_get_offset(&decoder->blkdec, offset);
}

int pt_insn_get_sync_offset(const struct pt_insn_decoder *decoder,
			    uint64_t *offset)
{
	if (!decoder)
		return -pte_invalid;

	return pt_blk_get_sync_offset(&decoder->blkdec, offset);
}

struct pt_image *pt_insn_get_image(struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_blk_get_image(&decoder->blkdec);
}

int pt_insn_set_image(struct pt_insn_decoder *decoder,
		      struct pt_image *image)
{
	if (!decoder)
		return -pte_invalid;

	return pt_blk_set_image(&decoder->blkdec, image);
}

const struct pt_config *
pt_insn_get_config(const struct pt_insn_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return pt_blk_config(&decoder->blkdec);
}

int pt_insn_time(struct pt_insn_decoder *decoder, uint64_t *time,
		 uint32_t *lost_mtc, uint32_t *lost_cyc)
{
	if (!decoder || !time)
		return -pte_invalid;

	return pt_blk_time(&decoder->blkdec, time, lost_mtc, lost_cyc);
}

int pt_insn_core_bus_ratio(struct pt_insn_decoder *decoder, uint32_t *cbr)
{
	if (!decoder || !cbr)
		return -pte_invalid;

	return pt_blk_core_bus_ratio(&decoder->blkdec, cbr);
}

int pt_insn_asid(const struct pt_insn_decoder *decoder, struct pt_asid *asid,
		 size_t size)
{
	if (!decoder || !asid)
		return -pte_invalid;

	return pt_blk_asid(&decoder->blkdec, asid, size);
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
		memset(((uint8_t *) uinsn) + sizeof(*insn), 0,
		       size - sizeof(*insn));

		size = sizeof(*insn);
	}

	memcpy(uinsn, insn, size);

	return 0;
}

static int pt_insn_decode_cached(struct pt_insn_decoder *decoder,
				 const struct pt_mapped_section *msec,
				 struct pt_insn *insn, struct pt_insn_ext *iext)
{
	int status;

	if (!decoder || !insn || !iext)
		return -pte_internal;

	/* Try reading the memory containing @insn from the cached section.  If
	 * that fails, if we don't have a cached section, or if decode fails
	 * later on, fall back to decoding @insn from @decoder->blkdec.image.
	 *
	 * The latter will also handle truncated instructions that cross section
	 * boundaries.
	 */

	if (!msec)
		return pt_insn_decode(insn, iext, decoder->blkdec.image,
				      &decoder->blkdec.asid);

	status = pt_msec_read(msec, insn->raw, sizeof(insn->raw), insn->ip);
	if (status < 0) {
		if (status != -pte_nomap)
			return status;

		return pt_insn_decode(insn, iext, decoder->blkdec.image,
				      &decoder->blkdec.asid);
	}

	/* We initialize @insn->size to the maximal possible size.  It will be
	 * set to the actual size during instruction decode.
	 */
	insn->size = (uint8_t) status;

	status = pt_ild_decode(insn, iext);
	if (status < 0) {
		if (status != -pte_bad_insn)
			return status;

		return pt_insn_decode(insn, iext, decoder->blkdec.image,
				      &decoder->blkdec.asid);
	}

	return status;
}

static int pt_insn_msec_lookup(struct pt_insn_decoder *decoder,
			       const struct pt_mapped_section **pmsec)
{
	struct pt_msec_cache *scache;
	struct pt_image *image;
	uint64_t ip;
	int isid;

	if (!decoder || !pmsec)
		return -pte_internal;

	scache = &decoder->blkdec.scache;
	image = decoder->blkdec.image;
	ip = decoder->block.ip;

	isid = pt_msec_cache_read(scache, pmsec, image, ip);
	if (isid < 0) {
		if (isid != -pte_nomap)
			return isid;

		return pt_msec_cache_fill(scache, pmsec, image,
					  &decoder->blkdec.asid, ip);
	}

	return isid;
}

int pt_insn_next(struct pt_insn_decoder *decoder, struct pt_insn *uinsn,
		 size_t size)
{
	const struct pt_mapped_section *msec;
	struct pt_insn_ext iext;
	struct pt_insn insn, *pinsn;
	struct pt_block *block;
	int status;

	if (!uinsn || !decoder)
		return -pte_invalid;

	pinsn = size == sizeof(insn) ? uinsn : &insn;
	block = &decoder->block;

	/* Initialize the instruction in case of error returns. */
	memset(pinsn, 0, sizeof(*pinsn));
	pinsn->speculative = block->speculative;
	pinsn->isid = block->isid;
	pinsn->mode = block->mode;
	pinsn->ip = block->ip;

	/* Fetch the next block if the current one has become empty. */
	while (!block->ninsn) {
		/* Errors and events apply to the end of a block. */
		status = decoder->status;
		if (status < 0) {
			(void) insn_to_user(uinsn, size, pinsn);
			return status;
		}

		/* We should have indicated the event already at the previous
		 * pt_insn_next() or pt_insn_event() call.
		 */
		if (status & pts_event_pending) {
			(void) insn_to_user(uinsn, size, pinsn);
			return -pte_event_ignored;
		}

		status = pt_blk_next(&decoder->blkdec, block, sizeof(*block));
		decoder->status = status;

		/* Update the instruction.  We do it early to provide more
		 * information in case of errors.
		 */
		pinsn->speculative = block->speculative;
		pinsn->isid = block->isid;
		pinsn->mode = block->mode;
		pinsn->ip = block->ip;

		/* We're done if we found a non-empty block. */
		if (block->ninsn)
			break;

		/* The block is empty, so we can report errors. */
		if (status < 0) {
			(void) insn_to_user(uinsn, size, pinsn);
			return status;
		}

		/* There was an event hidden behind an empty block, which
		 * prevented it from getting indicated ahead of time.
		 */
		if (status & pts_event_pending) {
			(void) insn_to_user(uinsn, size, pinsn);
			return -pte_event_ignored;
		}
	}

	/* If the last instruction does not fit entirely into the block's
	 * section, the block decoder provides its raw bytes.
	 */
	if (block->truncated && (block->ninsn == 1)) {
		memcpy(pinsn->raw, block->raw, block->size);
		pinsn->size = block->size;

		status = pt_ild_decode(pinsn, &iext);
	} else {
		msec = NULL;
		if (block->isid) {
			status = pt_insn_msec_lookup(decoder, &msec);
			if (status < 0) {
				(void) insn_to_user(uinsn, size, pinsn);
				return status;
			}
		}

		status = pt_insn_decode_cached(decoder, msec, pinsn, &iext);
	}

	/* If decode fails, provide the incomplete instruction - the IP and
	 * mode fields are valid and may help diagnose the error.
	 */
	if (status < 0) {
		(void) insn_to_user(uinsn, size, pinsn);
		return status;
	}

	status = insn_to_user(uinsn, size, pinsn);
	if (status < 0)
		return status;

	/* We consumed one instruction.
	 *
	 * As long as there are instructions left in the block, defer status
	 * indications; we want our caller to call us again.
	 */
	block->ninsn -= 1;
	if (block->ninsn)
		return pt_insn_next_ip(&block->ip, pinsn, &iext);

	/* We should reach the end instruction. */
	if (block->ip != block->end_ip)
		return -pte_internal;

	return decoder->status;
}

int pt_insn_event(struct pt_insn_decoder *decoder, struct pt_event *event,
		  size_t size)
{
	int status;

	if (!decoder || !event)
		return -pte_invalid;

	/* We're not indicating events when we're in the middle of a block. */
	if (decoder->block.ninsn)
		return -pte_bad_query;

	status = pt_blk_event(&decoder->blkdec, event, size);
	if (status < 0)
		return status;

	decoder->status = status;

	return status;
}
