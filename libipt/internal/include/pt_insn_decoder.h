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

#ifndef __PT_INSN_DECODER_H__
#define __PT_INSN_DECODER_H__

#include "pt_query_decoder.h"
#include "pt_image.h"
#include "pt_retstack.h"
#include "pti-ild.h"

#include <inttypes.h>


struct pt_insn_decoder {
	/* The Intel(R) Processor Trace query decoder. */
	struct pt_query_decoder query;

	/* The image of the traced process. */
	struct pt_image image;

	/* The current Intel(R) Processor Trace event. */
	struct pt_event event;

	/* The call/return stack for ret compression. */
	struct pt_retstack retstack;

	/* The Intel(R) Processor Trace instruction (length) decoder. */
	pti_ild_t ild;

	/* The current IP. */
	uint64_t ip;

	/* The current execution mode. */
	enum pt_exec_mode mode;

	/* The status of the last decoder query. */
	int status;

	/* A collection of flags defining how to proceed flow reconstruction:
	 *
	 * - tracing is enabled.
	 */
	uint32_t enabled:1;

	/* - process @event. */
	uint32_t process_event:1;

	/* - event processing may change the IP. */
	uint32_t event_may_change_ip:1;

	/* - instructions are executed speculatively. */
	uint32_t speculative:1;
};


/* Reset an instruction flow decoder.
 *
 * Resets all of @decoder's fields except for @image.
 */
extern void pt_insn_reset(struct pt_insn_decoder *decoder);

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

#endif /* __PT_INSN_DECODER_H__ */
