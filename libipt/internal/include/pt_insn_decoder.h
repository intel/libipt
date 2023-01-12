/*
 * Copyright (c) 2013-2023, Intel Corporation
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

#include "pt_query_decoder.h"
#include "pt_image.h"
#include "pt_retstack.h"

#include <inttypes.h>


struct pt_insn_decoder {
	/* The Intel(R) Processor Trace query decoder. */
	struct pt_query_decoder query;

	/* The configuration flags.
	 *
	 * Those are our flags set by the user.  In @query.config.flags, we set
	 * the flags we need for the query decoder.
	 */
	struct pt_conf_flags flags;

	/* The default image. */
	struct pt_image default_image;

	/* The image. */
	struct pt_image *image;

	/* The current address space. */
	struct pt_asid asid;

	/* The current Intel(R) Processor Trace event. */
	struct pt_event event;

	/* The call/return stack for ret compression. */
	struct pt_retstack retstack;

	/* The current IP. */
	uint64_t ip;

	/* The IP of the last disable.
	 *
	 * This is either zero or the IP of the first instruction that wasn't
	 * executed due to the disable event.
	 */
	uint64_t last_disable_ip;

	/* The current execution mode. */
	enum pt_exec_mode mode;

	/* The status of the last successful decoder query.
	 *
	 * Errors are reported directly; the status is always a non-negative
	 * pt_status_flag bit-vector.
	 */
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

	/* - a paging event has been bound to the current instruction. */
	uint32_t paging_event_bound:1;

	/* - a vmcs event has been bound to the current instruction. */
	uint32_t vmcs_event_bound:1;
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
