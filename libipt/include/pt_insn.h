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

#ifndef __PT_INSN_H__
#define __PT_INSN_H__

#include "pt_compiler.h"
#include "pt_opcode.h"

#include <stdint.h>

struct pt_config;


/* The maximal size of an instruction. */
enum {
	pt_max_insn_size	= 15
};

/* The instruction class.
 *
 * We provide only a very coarse classification suitable for reconstructing
 * the execution flow.
 */
enum pt_insn_class {
	/* The instruction could not be classified. */
	ptic_error,

	/* The instruction is something not listed below. */
	ptic_other,

	/* The instruction is a near (function) call. */
	ptic_call,

	/* The instruction is a near (function) return. */
	ptic_return,

	/* The instruction is a near unconditional jump. */
	ptic_jump,

	/* The instruction is a near conditional jump. */
	ptic_cond_jump
};

/* A single traced instruction. */
struct pt_insn {
	/* The virtual address in its process. */
	uint64_t ip;

	/* A coarse classification. */
	enum pt_insn_class iclass;

	/* The execution mode. */
	enum pt_exec_mode mode;

	/* The raw bytes. */
	uint8_t raw[pt_max_insn_size];

	/* The size in bytes. */
	uint8_t size;

	/* A collection of flags giving additional information:
	 *
	 * - the instruction was executed speculatively.
	 */
	uint32_t speculative:1;

	/* - speculative execution was aborted after this instruction. */
	uint32_t aborted:1;

	/* - speculative execution was committed after this instruction. */
	uint32_t committed:1;

	/* - tracing was enabled at this instruction. */
	uint32_t enabled:1;

	/* - tracing was disabled after this instruction. */
	uint32_t disabled:1;

	/* - normal execution flow was interrupted after this instruction. */
	uint32_t interrupted:1;

	/* - tracing resumed at this instruction after an overflow. */
	uint32_t resynced:1;
};

/* An Intel(R) Processor Trace instruction flow decoder. */
struct pt_insn_decoder;


/* Allocate an Intel(R) Processor Trace instruction flow decoder.
 *
 * The decoder will work on the PT buffer specified in the PT configuration.
 * The buffer shall contain raw trace data and remain valid for the lifetime of
 * the instruction flow decoder.
 *
 * The instruction flow decoder needs to be synchronized before it can be used.
 */
extern pt_export struct pt_insn_decoder *
pt_insn_alloc(const struct pt_config *);

/* Free an Intel(R) Processor Trace instruction flow decoder.
 *
 * The decoder object must not be used after a successful return.
 */
extern pt_export void pt_insn_free(struct pt_insn_decoder *);

/* Synchronize the Intel(R) Processor Trace instruction flow decoder.
 *
 * Search for the next synchronization point in forward or backward direction.
 *
 * If the instruction flow decoder has not been synchronized, yet, the search
 * is started at the beginning of the trace buffer in case of forward
 * synchronization and at the end of the trace buffer in case of backward
 * synchronization.
 *
 * Returns zero on success.
 *
 * Returns -pte_invalid if @decoder is NULL.
 * Returns -pte_eos if no further synchronization point is found.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_insn_sync_forward(struct pt_insn_decoder *decoder);
extern pt_export int pt_insn_sync_backward(struct pt_insn_decoder *decoder);

/* Return the offset into the Intel(R) Processor Trace buffer.
 *
 * Returns zero if @decoder is NULL.
 */
extern pt_export uint64_t pt_insn_get_offset(struct pt_insn_decoder *decoder);

/* Return the current time.
 *
 * This returns the time stamp count at the decoder's current position. Since
 * the decoder is reading ahead, the value does not necessarily match the time
 * at the previous or next instruction.
 *
 * The value should be good enough for a course correlation with other time-
 * stamped data such as side-band information.
 *
 * Returns zero if @decoder is NULL.
 */
extern pt_export uint64_t pt_insn_get_time(struct pt_insn_decoder *decoder);

/* Add a new file section to the traced process image.
 *
 * Add @size bytes starting at @offset in @filename.  The section is loaded
 * at the virtual address @vaddr in the traced process.
 *
 * The section is silently truncated to match the size of @filename.
 *
 * Returns zero on success, a negative error code otherwise.
 * Returns -pte_invalid if @decoder or @filename are NULL or if @offset is too big.
 * Returns -pte_bad_context sections would overlap.
 */
extern pt_export int pt_insn_add_file(struct pt_insn_decoder *decoder,
				      const char *filename, uint64_t offset,
				      uint64_t size, uint64_t vaddr);

/* Remove all sections loaded from a file from the traced process image.
 *
 * Removes all sections loaded from @filename.
 *
 * Returns the number of removed sections on success.
 * Returns -pte_invalid if @decoder or @filename are NULL.
 */
extern pt_export int pt_insn_remove_by_filename(struct pt_insn_decoder *decoder,
						const char *filename);

/* Determine the next instruction in execution order.
 *
 * On success, fills in @insn.
 *
 * Returns zero on success, a negative error code, otherwise.
 * Returns -pte_invalid if @decoder or @insn are NULL.
 * Returns -pte_eos if decoding reached the end of the PT buffer.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 * Returns -pte_nomap if the memory at the instruction address can't be read.
 */
extern pt_export int pt_insn_next(struct pt_insn_decoder *decoder,
				  struct pt_insn *insn);

#endif /* __PT_INSN_H__ */
