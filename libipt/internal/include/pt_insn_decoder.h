/*
 * Copyright (C) 2013-2026 Intel Corporation
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

#ifndef PT_INSN_DECODER_H
#define PT_INSN_DECODER_H

#include "pt_block_decoder.h"


struct pt_insn_decoder {
	/* The Intel(R) Processor Trace block decoder. */
	struct pt_block_decoder blkdec;

	/* The configuration flags.
	 *
	 * Those are our flags set by the user.  In @blkdec.config.flags, we
	 * set the flags we need for the block decoder.
	 */
	struct pt_conf_flags flags;

	/* The current block. */
	struct pt_block block;

	/* The status of the last successful block decoder query.
	 *
	 * We defer status returns until the current block has become empty.
	 */
	int status;
};


/* Initialize an instruction flow decoder.
 *
 * Returns zero on success; a negative error code otherwise.
 * Returns -pte_internal, if @decoder is NULL.
 * Returns -pte_invalid, if @config is NULL.
 */
extern int pt_insn_decoder_init(struct pt_insn_decoder *decoder,
				const struct pt_config *config);

/* Finalize an instruction flow decoder. */
extern void pt_insn_decoder_fini(struct pt_insn_decoder *decoder);

#endif /* PT_INSN_DECODER_H */
