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

#ifndef __PT_DECODE_H__
#define __PT_DECODE_H__

#include "pt_compiler.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct pt_config;
struct pt_decoder;


/* Allocate an Intel(R) Processor Trace decoder.
 *
 * The decoder will work on the buffer defined via its base address and size.
 * The buffer shall contain raw trace data and remain valid for the lifetime of
 * the decoder.
 *
 * The decoder needs to be synchronized before it can be used.
 */
extern pt_export struct pt_decoder *pt_alloc_decoder(const struct pt_config *);

/* Free an Intel(R) Processor Trace decoder.
 *
 * The decoder object must not be used after a successful return.
 */
extern pt_export void pt_free_decoder(struct pt_decoder *);

/* Get the current decoder position.
 *
 * This is useful when reporting errors.
 *
 * Returns the offset into the pt buffer at the current position.
 * Returns 0, if no decoder is given or the decoder as not been synchronized.
 */
extern pt_export uint64_t pt_get_decoder_pos(struct pt_decoder *);

/* Get the position of the last synchronization point.
 *
 * This is useful when splitting a trace stream for parallel decoding.
 *
 * Returns the offset into the pt buffer for the last synchronization point.
 * Returns 0, if no decoder is given or the decoder as not been synchronized.
 */
extern pt_export uint64_t pt_get_decoder_sync(struct pt_decoder *);

/* Get a pointer into the raw PT buffer at the decoder's current position. */
extern pt_export const uint8_t *pt_get_decoder_raw(const struct pt_decoder *);

/* Get a pointer to the beginning of the raw PT buffer. */
extern pt_export const uint8_t *pt_get_decoder_begin(const struct pt_decoder *);

/* Get a pointer to the end of the raw PT buffer. */
extern pt_export const uint8_t *pt_get_decoder_end(const struct pt_decoder *);

/* Synchronize the decoder.
 *
 * Search for the next synchronization point in forward or backward direction.
 *
 * If the decoder has not been synchronized, yet, the search is started at the
 * beginning of the trace buffer in case of forward synchronization and at the
 * end of the trace buffer in case of backward synchronization.
 *
 * Returns zero on success.
 *
 * Returns -pte_invalid if no decoder is given.
 * Returns -pte_eos if no further synchronization point is found.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_sync_forward(struct pt_decoder *);
extern pt_export int pt_sync_backward(struct pt_decoder *);

/* Advance the decoder.
 *
 * Adjust @decoder's position by @size bytes.
 *
 * Returns zero on success.
 *
 * Returns -pte_invalid if no decoder is given.
 * Returns -pte_eos if the adjusted position would be outside of the PT buffer.
 */
extern pt_export int pt_advance(struct pt_decoder *decoder, int size);

#endif /* __PT_DECODE_H__ */
