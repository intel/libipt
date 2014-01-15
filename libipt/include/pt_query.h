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

#ifndef __PT_QUERY_H__
#define __PT_QUERY_H__

#include "pt_compiler.h"
#include "pt_opcode.h"

#include <stdint.h>

struct pt_decoder;


/* Intel(R) Processor Trace status flags. */
enum pt_status_flag {
	/* There is an event pending. */
	pts_event_pending	= 1 << 0,

	/* The destination address has been suppressed due to CPL filtering. */
	pts_ip_suppressed	= 1 << 1
};

/* An Intel(R) Processor Trace event type. */
enum pt_event_type {
	/* Tracing has been enabled/disabled wrt filtering. */
	ptev_enabled,
	ptev_disabled,

	/* Tracing has been disabled asynchronously wrt filtering. */
	ptev_async_disabled,

	/* An asynchronous branch, e.g. interrupt. */
	ptev_async_branch,

	/* A synchronous paging event. */
	ptev_paging,

	/* An asynchronous paging event. */
	ptev_async_paging,

	/* Trace overflow. */
	ptev_overflow,

	/* An execution mode change. */
	ptev_exec_mode,

	/* A transactional execution state change. */
	ptev_tsx
};

/* An Intel(R) Processor Trace event. */
struct pt_event {
	/* The type of the event. */
	enum pt_event_type type;

	/* A flag indicating that the event IP had been suppressed. */
	uint32_t ip_suppressed:1;

	/* A flag indicating that the event is for status update. */
	uint32_t status_update:1;

	/* Event specific data. */
	union {
		/* Event: enabled. */
		struct {
			/* The address at which tracing resumes. */
			uint64_t ip;
		} enabled;

		/* Event: disabled. */
		struct {
			/* The destination of the first branch inside a
			 * filtered area.
			 *
			 * This field is not valid, if pts_ip_suppressed is
			 * returned from the query function.
			 */
			uint64_t ip;

			/* The exact source ip needs to be determined using
			 * disassembly and the filter configuration.
			 */
		} disabled;

		/* Event: async disabled. */
		struct {
			/* The source address of the asynchronous branch that
			 * disabled tracing.
			 */
			uint64_t at;

			/* The destination of the first branch inside a
			 * filtered area.
			 *
			 * This field is not valid, if pts_ip_suppressed is
			 * returned from the query function.
			 */
			uint64_t ip;
		} async_disabled;

		/* Event: async branch. */
		struct {
			/* The branch source address. */
			uint64_t from;

			/* The branch destination address.
			 *
			 * This field is not valid, if pts_ip_suppressed is
			 * returned from the query function.
			 */
			uint64_t to;
		} async_branch;

		/* Event: paging. */
		struct {
			/* The updated CR3 value.
			 *
			 * The lower 5 bit have been zeroed out.
			 * The upper bits have been zeroed out depending on the
			 * maximum possible address.
			 */
			uint64_t cr3;

			/* The address at which the event is effective is
			 * obvious from the disassembly.
			 */
		} paging;

		/* Event: async paging. */
		struct {
			/* The updated CR3 value.
			 *
			 * The lower 5 bit have been zeroed out.
			 * The upper bits have been zeroed out depending on the
			 * maximum possible address.
			 */
			uint64_t cr3;

			/* The address at which the event is effective. */
			uint64_t ip;
		} async_paging;

		/* Event: overflow. */
		struct {
			/* The address at which tracing resumes after overflow.
			 */
			uint64_t ip;
		} overflow;

		/* Event: exec mode. */
		struct {
			/* The execution mode. */
			enum pt_exec_mode mode;

			/* The address at which the event is effective. */
			uint64_t ip;
		} exec_mode;

		/* Event: tsx. */
		struct {
			/* The address at which the event is effective.
			 *
			 * This field is not valid, if pts_ip_suppressed is
			 * returned from the query function.
			 */
			uint64_t ip;

			/* A flag indicating speculative execution mode. */
			uint32_t speculative:1;

			/* A flag indicating speculative execution aborts. */
			uint32_t aborted:1;
		} tsx;
	} variant;
};


/* Start querying.
 *
 * Read ahead until the first query-relevant packet and return the current
 * query status.
 *
 * This function must be called once after synchronizing the decoder.
 *
 * On success, if the second parameter is not NULL, provides the linear address
 * of the first instruction in it, unless the address has been suppressed. In
 * this case, the address is set to zero.
 *
 * Returns a non-negative pt_status_flag bit-vector on success.
 *
 * Returns -pte_invalid if no decoder is given.
 * Returns -pte_nosync if the decoder is out of sync.
 * Returns -pte_eos if the end of the trace buffer is reached.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_query_start(struct pt_decoder *, uint64_t *);

/* Get the next unconditional branch destination.
 *
 * On success, provides the linear destination address of the next unconditional
 * branch in the second parameter, provided it is not null, and updates the
 * decoder state accordingly.
 *
 * Returns a non-negative pt_status_flag bit-vector on success.
 *
 * Returns -pte_invalid if no decoder or no address is given.
 * Returns -pte_nosync if the decoder is out of sync.
 * Returns -pte_bad_query if no unconditional branch destination is found.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_query_uncond_branch(struct pt_decoder *, uint64_t *);

/* Query whether the next unconditional branch has been taken.
 *
 * On success, provides 1 (taken) or 0 (not taken) in the second parameter for
 * the next conditional branch and updates the decoder state accordingly.
 *
 * Returns a non-negative pt_status_flag bit-vector on success.
 *
 * Returns -pte_invalid if no decoder or no address is given.
 * Returns -pte_nosync if the decoder is out of sync.
 * Returns -pte_bad_query if no conditional branch is found.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_query_cond_branch(struct pt_decoder *, int *);

/* Query the next pending event.
 *
 * On success, provides the next event in the second parameter and updates the
 * decoder state accordingly.
 *
 * Returns a non-negative pt_status_flag bit-vector on success.
 *
 * Returns -pte_invalid if no decoder or no address is given.
 * Returns -pte_nosync if the decoder is out of sync.
 * Returns -pte_bad_query if no event is found.
 * Returns -pte_bad_opc if the decoder encountered unknown packets.
 * Returns -pte_bad_packet if the decoder encountered unknown packet payloads.
 */
extern pt_export int pt_query_event(struct pt_decoder *, struct pt_event *);

/* Query the current time stamp count.
 *
 * This returns the time stamp count at the decoder's current position. Since
 * the decoder is reading ahead until the next unconditional branch or event,
 * the value matches the time stamp count for that branch or event.
 *
 * The time stamp count is similar to what an rdtsc instruction would return.
 *
 * Beware that the time stamp count is no fully accurate and that it is updated
 * irregularly.
 *
 * Returns the current time stamp count.
 * Returns 0 if no time stamp count is available.
 * Returns 0 if no decoder or a corrupted decoder is given.
 */
extern pt_export uint64_t pt_query_time(struct pt_decoder *);

#endif /* __PT_QUERY_H__ */
