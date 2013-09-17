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

#ifndef __DECODE_H__
#define __DECODE_H__

#include <stdint.h>

struct pt_decoder;
struct load_map;
struct disas_state;


/* Proceed one instruction.
 *
 * Returns a pt_status_flag bit-vector on success.
 * Returns a negative error code otherwise.
 */
extern int proceed(struct disas_state *);

/* Proceed to the given location.
 *
 * Returns when the location is reached without fetching the instruction at that
 * location.
 *
 * If the pf_ignore_events flag is set, also returns when an event is
 * pending, again without fetching the instruction at the current ip.
 *
 * Returns a pt_status_flag bit-vector on success.
 * Returns a negative error code otherwise.
 */
extern int proceed_to_ip(struct disas_state *, uint64_t);

/* Proceed to the next instruction satisfying @pred.
 *
 * Returns when the location is reached after fetching the instruction at that
 * location.
 *
 * If the pf_ignore_events flag is set, also returns when an event is
 * pending without fetching the instruction at the current ip.
 *
 * Returns a pt_status_flag bit-vector on success.
 * Returns a negative error code otherwise.
 */
extern int proceed_to_inst(struct disas_state *,
			   int (*pred)(struct disas_state *));

/* Disassemble the entire trace as far as possible.
 *
 * Resync if necessary.
 */
extern void disas(struct pt_decoder *, struct load_map *);

#endif /* __DECODE_H__ */
