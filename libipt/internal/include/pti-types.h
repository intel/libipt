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

#if !defined(_PTI_TYPES_H_)
#define _PTI_TYPES_H_


#if defined(__GNUC__) || defined(__ICC)
#include <stdint.h>
#define pti_uint8_t   uint8_t
#define pti_uint16_t  uint16_t
#define pti_uint32_t  uint32_t
#define pti_uint64_t  uint64_t
#define pti_int8_t     int8_t
#define pti_int16_t 	 int16_t
#define pti_int32_t    int32_t
#define pti_int64_t    int64_t
#elif defined(_WIN32)
#define pti_uint8_t  unsigned __int8
#define pti_uint16_t unsigned __int16
#define pti_uint32_t unsigned __int32
#define pti_uint64_t unsigned __int64
#define pti_int8_t   __int8
#define pti_int16_t  __int16
#define pti_int32_t  __int32
#define pti_int64_t  __int64
#else
#error "PTI types unsupported platform? Need windows, gcc, or icc."
#endif

typedef unsigned int pti_uint_t;
typedef int pti_int_t;
typedef unsigned int pti_bits_t;
typedef unsigned int pti_bool_t;

#endif
