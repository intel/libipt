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

#if !defined(_PTI_DEFS_H_)
#define _PTI_DEFS_H_


#if defined(__FreeBSD__)
#define PTI_BSD
#endif
#if defined(__linux__)
#define PTI_LINUX
#endif
#if defined(_MSC_VER)
#define PTI_WINDOWS
#endif
#if defined(__APPLE__)
#define PTI_MAC
#endif

#if defined(PTI_DLL)
/*  __declspec(dllexport) works with GNU GCC or MS compilers, but not ICC
    on linux */

#if defined(PTI_WINDOWS)
#define PTI_DLL_EXPORT __declspec(dllexport)
#define PTI_DLL_IMPORT __declspec(dllimport)
#elif defined(PTI_LINUX)  || defined(PTI_BSD) || defined(PTI_MAC)
#define PTI_DLL_EXPORT __attribute__((visibility("default")))
#define PTI_DLL_IMPORT
#else
#define PTI_DLL_EXPORT
#define PTI_DLL_IMPORT
#endif
#else
#define PTI_DLL_EXPORT
#define PTI_DLL_IMPORT
#endif


#if defined(_WIN32) && defined(_MSC_VER)
#if _MSC_VER == 1200
#define PTI_MSVC6 1
#endif
#endif

#if defined(__GNUC__)
#define PTI_INLINE static inline
#define PTI_NORETURN __attribute__ ((noreturn))
#if __GNUC__ == 2
#define PTI_NOINLINE
#else
#define PTI_NOINLINE __attribute__ ((noinline))
#endif
#else
#define PTI_INLINE static __inline
#if defined(PTI_MSVC6)
#define PTI_NOINLINE
#else
#define PTI_NOINLINE __declspec(noinline)
#endif
#define PTI_NORETURN __declspec(noreturn)
#endif


#endif
