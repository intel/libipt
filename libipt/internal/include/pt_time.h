/*
 * Copyright (c) 2014, Intel Corporation
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

#ifndef __PT_TIME_H__
#define __PT_TIME_H__

#include <stdint.h>

struct pt_config;
struct pt_packet_tsc;
struct pt_packet_cbr;


/* Intel(R) Processor Trace timing. */
struct pt_time {
	/* The measured Time Stamp Count. */
	uint64_t tsc;

	/* The core:bus ratio. */
	uint8_t cbr;
};

/* Initialize (or reset) the time. */
extern void pt_time_init(struct pt_time *time);

/* Query the current time.
 *
 * Provides the Time Stamp Count value in @tsc.
 *
 * Returns zero on success; a negative error code, otherwise.
 * Returns -pte_invalid if @tsc or @time is NULL.
 */
extern int pt_time_query_tsc(uint64_t *tsc, const struct pt_time *time);

/* Query the current core:bus ratio.
 *
 * Provides the core:bus ratio in @cbr.
 *
 * Returns zero on success; a negative error code, otherwise.
 * Returns -pte_invalid if @cbr or @time is NULL.
 */
extern int pt_time_query_cbr(uint32_t *cbr, const struct pt_time *time);

/* Update the time based on an Intel PT packet.
 *
 * Returns zero on success.
 * Returns a negative error code, otherwise.
 */
extern int pt_time_update_tsc(struct pt_time *, const struct pt_packet_tsc *,
			      const struct pt_config *);
extern int pt_time_update_cbr(struct pt_time *, const struct pt_packet_cbr *,
			      const struct pt_config *);

#endif /* __PT_TIME_H__ */
