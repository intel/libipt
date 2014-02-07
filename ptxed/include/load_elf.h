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

#ifndef __LOAD_ELF_H__
#define __LOAD_ELF_H__

#include <stdint.h>

struct pt_insn_decoder;


/* Load an ELF file.
 *
 * Adds sections for all ELF LOAD segments.
 *
 * The sections are loaded relative to their virtual addresses specified
 * in the ELF program header with the lowest address section loaded at @base.
 *
 * The name of the program in @prog is used for error reporting.
 * If @verbose is non-zero, prints information about loaded sections.
 *
 * Does not load dependent files.
 * Does not support dynamic relocations.
 *
 * Successfully loaded segments are not unloaded in case of errors.
 *
 * Returns 0 on success, a negative error code otherwise.
 * Returns -pte_invalid if @image or @file are NULL.
 * Returns -pte_bad_config if @file can't be processed.
 * Returns -pte_nomem if not enough memory can be allocated.
 */
extern int load_elf(struct pt_insn_decoder *decoder, const char *file,
		    uint64_t base, const char *prog, int verbose);

#endif /* __LOAD_ELF_H__ */
