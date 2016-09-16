/*
 * Copyright (c) 2017-2018, Intel Corporation
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

#ifndef PT_ELF_H
#define PT_ELF_H

#include <stdint.h>

struct pt_image_section_cache;
struct pt_image;


/* A collection of flags. */
enum pt_elf_flags {
	/* Print information about loaded segments. */
	pte_verbose	= 1 << 0
};

/* Load executable segments from an ELF file.
 *
 * Adds a section to @image for each executable segment in @filename.
 *
 * If @base is non-zero, the load addresses are modified such that the first
 * segment is loaded at @base.
 *
 * If pte_verbose is set in @flags, prints information about the loaded
 * segments to stdout.
 *
 * If @iscache is not NULL, adds sections to @iscache and from there to @image.
 *
 * Returns the number of added image sections on success, a negative
 * pt_error_code otherwise.
 * Returns -pte_internal if @image or @filename is NULL.
 * Returns -pte_bad_file if @filename is not an ELF file.
 * Returns -pte_nomem if not enough memory can be allocated.
 */
extern int pt_elf_load_segments(struct pt_image_section_cache *iscache,
				struct pt_image *image, const char *filename,
				uint64_t base, uint32_t flags);

#endif /* PT_ELF_H */
