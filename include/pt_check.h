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

#ifndef __PT_CHECK__
#define __PT_CHECK__

#include <check.h>
#include <inttypes.h>

/* Check comparison macros for pointers. */
#define ck_null(P) \
	ck_assert_msg((P) == NULL, "NULL assertion failed: '"#P"=%p'", P)
#define ck_nonnull(P) \
	ck_assert_msg((P) != NULL, "Non-NULL assertion failed for '"#P"'", P)
#define ck_ptr(P, Q) \
	ck_assert_msg((P) == (Q),\
		      "Assertion '"#P"=="#Q"' failed: ""'"#P"=%p', "#Q"=%p'",\
		      P, Q)

/* Check comparison macros for uint64_t. */
#define ck_uint64_eq(X, Y) \
	ck_assert_msg((X) == (Y),\
		      "Assertion '"#X"=="#Y"' failed: ""'"#X"=0x%" PRIx64 \
		      "', "#Y"=0x%" PRIx64 "'", X, Y)
#define ck_uint64_ne(X, Y) \
	ck_assert_msg((X) != (Y),\
		      "Assertion '"#X"!="#Y"' failed: ""'"#X"=0x%" PRIx64 \
		      "', "#Y"=0x%" PRIx64 "'", X, Y)

/* Wrappers for int macros. */
#define ck_int_eq(X, Y) ck_assert_int_eq(X, Y)
#define ck_int_ne(X, Y) ck_assert_int_ne(X, Y)
#define ck_int_ge(X, Y) _ck_assert_int(X, >=, Y)
#define ck_int_gt(X, Y) _ck_assert_int(X, >, Y)

/* Check comparison macros for uint. */
#define ck_uint_eq(X, Y) ck_assert_int_eq(X, Y)
#define ck_uint_ne(X, Y) ck_assert_int_ne(X, Y)

/* Check comparison macros for int-as-bool. */
#define ck_false(B) ck_assert_int_eq(B, 0)
#define ck_true(B) ck_assert_int_ne(B, 0)

#endif /* __PT_CHECK__ */
