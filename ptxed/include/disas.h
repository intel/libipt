/*
 * Copyright (c) 2013, Intel Corporation
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

#ifndef __DISAS_H__
#define __DISAS_H__

#include "pt_query.h"
#include "pt_error.h"

#include <xed-state.h>
#include <xed-decoded-inst.h>
#include <stdint.h>

struct load_map;


/* Flags specifying the allowed operations during proceeding. */
enum proceed_flag {
	/* Ignore pending events. */
	pf_ignore_events	= 1 << 0,

	/* The code is executed speculatively. */
	pf_speculative		= 1 << 1,

	/* Returns are compressed. */
	pf_ptev_compression	= 1 << 2,

	/* Tracing is temporarily disabled. */
	pf_pt_disabled		= 1 << 3,

	/* Suppress instruction printing.  */
	pf_no_inst		= 1 << 4
};

enum {
	/* The max number of calls in the call buffer. */
	ds_call_max = 64
};

struct disas_state {
	/* The XED disassembler state. */
	xed_state_t xed;

	/* The current decoded instruction. */
	xed_decoded_inst_t inst;

	/* The current ip. */
	uint64_t ip;

	/* A bit-vector of proceed flags. */
	int flags;

	/* The next pending event, if any. */
	struct pt_event event;

	/* The Intel(R) Processor Trace decoder. */
	struct pt_decoder *decoder;

	/* The ELF load map. */
	struct load_map *elfmap;

	/* The ret compression call buffer. */
	uint64_t calls[ds_call_max];
	uint8_t call_top;
};

/* An address-based disassembly filter.
 *
 * If at least one filter is present,instructions that do not fall into any of
 * the filter ranges are suppressed.
 *
 * Use disas_is_suppressed() to query the above property.
 */
struct disas_filter {
	/* The next filter in a linear list of filters. */
	struct disas_filter *next;

	/* The begin and end linear address of this filter. The filtered range
	 * is [begin; end[.
	 */
	uint64_t begin, end;
};

/* Initialize the disassembler state. */
extern void disas_init(struct disas_state *, struct pt_decoder *,
		       struct load_map *);

/* Set the execution mode for the disassembler.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
extern int disas_set_exec_mode(struct disas_state *, enum pt_exec_mode);

/* Check the execution mode of the disassembler.
 *
 * Returns 0 if the modes match.
 * Returns 1 if the modes differ.
 * Returns a negative error code otherwise.
 */
extern int disas_check_exec_mode(struct disas_state *, enum pt_exec_mode);

/* Set the speculation mode for the disassembler.
 *
 * A non-zero mode means speculation is on; zero means it is off.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
extern int disas_set_speculation_mode(struct disas_state *, int);

/* Check the speculation mode of the disassembler.
 *
 * A non-zero mode means speculation is on; zero means it is off.
 *
 * Returns 0 if the modes match.
 * Returns 1 if the modes differ.
 * Returns a negative error code otherwise.
 */
extern int disas_check_speculation_mode(struct disas_state *, int);

/* Decode the instruction at the state's current ip.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
extern int disas_decode_inst(struct disas_state *);

/* Print the previously decoded instruction.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
extern int disas_print_inst(struct disas_state *);

/* Return the size of the previously decoded instruction.
 *
 * Returns the size in bytes on success.
 * Returns a negative error code otherwise.
 */
extern int disas_get_inst_size(struct disas_state *);

/* Determine if the instruction changes cr3.
 *
 * Returns 0 if the previously decoded instruction does not change cr3.
 * Returns 1 if the previously decoded instruction changes cr3.
 * Returns a negative error code otherwise.
 */
extern int disas_inst_changes_cr3(struct disas_state *);

/* Determine if the instruction changes exec mode.
 *
 * Returns 0 if the previously decoded instruction does not change exec mode.
 * Returns 1 if the previously decoded instruction changes exec mode.
 * Returns a negative error code otherwise.
 */
extern int disas_inst_changes_exec_mode(struct disas_state *);

/* Determine if the instruction changes cpl.
 *
 * Returns 0 if the previously decoded instruction does not change cpl.
 * Returns 1 if the previously decoded instruction changes cpl.
 * Returns a negative error code otherwise.
 */
extern int disas_inst_changes_cpl(struct disas_state *);

/* Push @ip onto the call stack.
 *
 * This is a nop if ret compression is not enabled.
 *
 * Returns 0 on success.
 * Returns a negative error code otherwise.
 */
extern int disas_push_call(struct disas_state *, uint64_t ip);

/* Pop the topmost ip from the call stack.
 *
 * The ip from the call stack is stored in the state's current ip.
 * This is a nop if ret compression is not enabled.
 *
 * Returns 0 if ret compression is not enabled.
 * Returns 1 if an address has been popped.
 * Returns a negative error code otherwise.
 */
extern int disas_pop_call(struct disas_state *);

/* Diagnose an error.
 *
 * Prints the error text plus the location in pt stream and disassembly.
 *
 * Returns -@err.
 */
extern int diag(const char *, struct disas_state *, enum pt_error_code err);

/* Add an address range to be focused on.
 *
 * Instructions in the range [begin; end[ will be printed.
 */
extern int disas_filter(uint64_t begin, uint64_t end);

/* Clear filters.
 *
 * Removes all existing filters, thus printing all instructions.
 */
extern void disas_clear_filters();

/* Check whether the instruction at @ip is suppressed.
 *
 * An address is suppressed if there is at least one filter and the address is
 * not contained in any of the filters.
 *
 * Returns 1 if the instruction at @ip is suppressed.
 * Returns 0 if the instruction at @ip is not suppressed.
 */
extern int disas_is_suppressed(uint64_t ip);

#endif /* __DISAS_H__ */
