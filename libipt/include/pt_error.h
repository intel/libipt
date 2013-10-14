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

#ifndef __PT_ERROR_H__
#define __PT_ERROR_H__

#include "pt_compiler.h"


/* Intel(R) Processor Trace error codes. */
enum pt_error_code {
	/* No error. Everything is OK. */
	pte_ok,

	/* Internal decoder error. */
	pte_internal,

	/* Invalid argument. */
	pte_invalid,

	/* Decoder out of sync. */
	pte_nosync,

	/* Unknown opcode. */
	pte_bad_opc,

	/* Unknown payload. */
	pte_bad_packet,

	/* Unexpected packet context. */
	pte_bad_context,

	/* Decoder reached end of trace stream. */
	pte_eos,

	/* No packet matching the query to be found. */
	pte_bad_query,

	/* Decoder out of memory. */
	pte_nomem,

	/* Bad configuration. */
	pte_bad_config,

	/* There is no IP. */
	pte_noip,

	/* The IP has been suppressed. */
	pte_ip_suppressed,

	/* There is no memory mapped at the requested address. */
	pte_nomap,

	/* An instruction could not be decoded. */
	pte_bad_insn
};


/* Decode a function return value into an pt_error_code. */
static inline enum pt_error_code pt_errcode(int status)
{
	return (status >= 0) ? pte_ok : (enum pt_error_code) -status;
}

/* Return a human readable error string. */
extern pt_export const char *pt_errstr(enum pt_error_code);

#endif /* __PT_ERROR_H__ */
