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

#include "disas.h"
#include "load.h"

#include "pt_decode.h"

#include <xed-init.h>
#include <xed-error-enum.h>
#include <xed-decode.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>


/* The disassembly filters. */
static struct disas_filter *filters;

static void ctor(void)
{
	static int xed;

	if (xed)
		return;

	xed_tables_init();
}

void disas_init(struct disas_state *state,
		struct pt_decoder *decoder, struct load_map *elfmap)
{
	/* HACK: mode
	 *
	 * Set the mode via command-line option until the spec is more clear
	 * about the default mode.
	 */
	extern enum pt_exec_mode opt_exec_mode;

	/* HACK: flags
	 *
	 * Sneak in some default disassembly flags that can be set via the
	 * command-line.
	 */
	extern int opt_pflags;

	if (!state)
		return;

	/* This could be done more elegantly but less portably using ctors. */
	ctor();

	memset(state, 0, sizeof(*state));

	xed_state_zero(&state->xed);
	state->decoder = decoder;
	state->elfmap = elfmap;
	state->flags = opt_pflags;

	(void) disas_set_exec_mode(state, opt_exec_mode);
}

int disas_set_exec_mode(struct disas_state *state, enum pt_exec_mode mode)
{
	if (!state)
		return -pte_internal;

	switch (mode) {
	case ptem_unknown:
		return -pte_bad_packet;

	case ptem_16bit:
		xed_state_set_machine_mode(&state->xed,
					   XED_MACHINE_MODE_LEGACY_16);
		return 0;

	case ptem_32bit:
		xed_state_set_machine_mode(&state->xed,
					   XED_MACHINE_MODE_LEGACY_32);
		return 0;

	case ptem_64bit:
		xed_state_set_machine_mode(&state->xed,
					   XED_MACHINE_MODE_LONG_64);
		return 0;
	}

	return -pte_internal;
}

int disas_check_exec_mode(struct disas_state *state, enum pt_exec_mode expected)
{
	xed_machine_mode_enum_t mode;

	if (!state)
		return -pte_internal;

	mode = xed_state_get_machine_mode(&state->xed);
	switch (expected) {
	case ptem_unknown:
		return -pte_bad_packet;

	case ptem_16bit:
		if (mode == XED_MACHINE_MODE_LEGACY_16)
			return 0;

		return 1;

	case ptem_32bit:
		if (mode == XED_MACHINE_MODE_LEGACY_32)
			return 0;

		return 1;

	case ptem_64bit:
		if (mode == XED_MACHINE_MODE_LONG_64)
			return 0;

		return 1;
	}

	return -pte_internal;
}

int disas_set_speculation_mode(struct disas_state *state, int speculative)
{
	if (!state)
		return -pte_internal;

	if (speculative)
		state->flags |= pf_speculative;
	else
		state->flags &= ~pf_speculative;

	return 0;
}

int disas_check_speculation_mode(struct disas_state *state, int expected)
{
	int mode;

	mode = state->flags & pf_speculative;

	if (mode && expected)
		return 0;

	if (!mode && !expected)
		return 0;

	return 1;
}

int disas_decode_inst(struct disas_state *state)
{
	xed_error_enum_t errcode;
	uint8_t *mem;
	uint64_t space;

	mem = translate(state->elfmap, state->ip, &space);
	if (!mem)
		return diag("no memory", state, pte_nosync);

	xed_decoded_inst_zero_set_mode(&state->inst, &state->xed);

	errcode = xed_decode(&state->inst, mem, (unsigned int) space);
	switch (errcode) {
	case XED_ERROR_NONE:
		return 0;

	default:
		return -pte_bad_packet;
	}
}

int disas_print_inst(struct disas_state *state)
{
	char buffer[256];
	xed_bool_t ok;

	ok = xed_decoded_inst_dump_intel_format(&state->inst, buffer,
						sizeof(buffer), state->ip);
	if (!ok)
		return diag("bad inst", state, pte_nosync);

	printf("0x%016" PRIx64, state->ip);
	if (!(state->flags & pf_no_inst))
		printf("  %s", buffer);

	return 0;
}

int disas_get_inst_size(struct disas_state *state)
{
	return xed_decoded_inst_get_length(&state->inst);
}

int disas_inst_changes_cr3(struct disas_state *state)
{
	switch (xed_decoded_inst_get_category(&state->inst)) {
	default:
		return 0;
	}
}

int disas_inst_changes_exec_mode(struct disas_state *state)
{
	switch (xed_decoded_inst_get_category(&state->inst)) {
	default:
		return 0;
	}
}

int disas_inst_changes_cpl(struct disas_state *state)
{
	switch (xed_decoded_inst_get_category(&state->inst)) {
	default:
		return 0;

	case XED_CATEGORY_INTERRUPT:
	case XED_CATEGORY_SYSCALL:
	case XED_CATEGORY_SYSRET:
	case XED_CATEGORY_SYSTEM:
		return 1;
	}
}

int disas_push_call(struct disas_state *state, uint64_t ip)
{
	if (state->flags & pf_ptev_compression) {
		state->calls[state->call_top] = ip;

		state->call_top += 1;
		state->call_top %= ds_call_max;
	}

	return 0;
}

int disas_pop_call(struct disas_state *state)
{
	if (!(state->flags & pf_ptev_compression))
		return diag("bad zret", state, pte_bad_packet);

	state->call_top -= 1;
	state->call_top %= ds_call_max;

	state->ip = state->calls[state->call_top];

	return 0;
}

int diag(const char *msg, struct disas_state *state, enum pt_error_code err)
{
	printf("[%" PRIx64 ", 0x%" PRIx64": %s]\n",
	       pt_get_decoder_pos(state->decoder), state->ip, msg);

	return -err;
}

int disas_filter(uint64_t begin, uint64_t end)
{
	struct disas_filter *next;

	next = malloc(sizeof(*next));
	if (!next)
		return -pte_nomem;

	next->next = filters;
	next->begin = begin;
	next->end = end;

	filters = next;

	return 0;
}

void disas_clear_filters()
{
	while (filters) {
		struct disas_filter *trash;

		trash = filters;
		filters = filters->next;

		free(trash);
	}
}

int disas_is_suppressed(uint64_t ip)
{
	struct disas_filter *it;

	if (!filters)
		return 0;

	for (it = filters; it; it = it->next) {
		if ((it->begin <= ip) && (ip < it->end))
			return 0;
	}

	return 1;
}
