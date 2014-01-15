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

#ifndef __PT_SECTION_H__
#define __PT_SECTION_H__

#include <stdint.h>
#include <stdio.h>


/* A section of contiguous memory loaded from a file. */
struct pt_section;

/* Create a section.
 *
 * The returned section describes the contents of @file starting at @offset
 * for @size bytes loaded at virtual address @addr.
 *
 * If @file is shorter than the requested @size, the section is silently
 * truncated to the size of @file.
 *
 * If @offset lies beyond the end of @file, no section is created.
 *
 * Returns a new section on success, NULL otherwise.
 */
extern struct pt_section *pt_mk_section(const char *file, uint64_t offset,
					uint64_t size, uint64_t addr);

/* Free a section.
 *
 * The @section must have been allocated by pt_mk_section() or be NULL.
 */
extern void pt_section_free(struct pt_section *section);

/* Return the filename of @section. */
extern const char *pt_section_filename(const struct pt_section *section);

/* Return the virtual address of the beginning of the memory region. */
extern uint64_t pt_section_begin(const struct pt_section *section);

/* Return the virtual address one byte past the end of the memory region. */
extern uint64_t pt_section_end(const struct pt_section *section);

/* Read memory from a section.
 *
 * Reads at most @size bytes from @section at @addr into @buffer.
 *
 * Returns the number of bytes read on success, a negative error code otherwise.
 * Returns -pte_invalid, if @section or @buffer are NULL.
 * Returns -pte_nomap, if the section does not contain @addr.
 */
extern int pt_section_read(struct pt_section *section, uint8_t *buffer,
			   uint16_t size, uint64_t addr);

#endif /* __PT_SECTION_H__ */
