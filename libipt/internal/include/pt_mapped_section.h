/*
 * Copyright (c) 2014-2015, Intel Corporation
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

#ifndef PT_MAPPED_SECTION_H
#define PT_MAPPED_SECTION_H

#include "intel-pt.h"

#include <stdint.h>

struct pt_section;


/* A section mapped into memory. */
struct pt_mapped_section {
	/* The section that is mapped. */
	struct pt_section *section;

	/* The address space into which the section is mapped. */
	struct pt_asid asid;

	/* The virtual address at which the section is mapped. */
	uint64_t vaddr;
};


/* Initialize a mapped section - @section may be NULL. */
extern void pt_msec_init(struct pt_mapped_section *msec,
			 struct pt_section *section, const struct pt_asid *asid,
			 uint64_t vaddr);

/* Destroy a mapped section - does not free @msec->section. */
extern void pt_msec_fini(struct pt_mapped_section *msec);

/* Return the virtual address of the beginning of the memory region. */
extern uint64_t pt_msec_begin(const struct pt_mapped_section *msec);

/* Return the virtual address one byte past the end of the memory region. */
extern uint64_t pt_msec_end(const struct pt_mapped_section *msec);

/* Return an identifier for the address-space the section is mapped into. */
extern const struct pt_asid *pt_msec_asid(const struct pt_mapped_section *msec);

/* Check if a section matches an asid.
 *
 * Returns a positive number if @msec matches @asid.
 * Returns zero if @msec does not match @asid.
 * Returns a negative error code otherwise.
 *
 * Returns -pte_internal if @msec or @asid are NULL.
 */
extern int pt_msec_matches_asid(const struct pt_mapped_section *msec,
				const struct pt_asid *asid);

/* Read memory from a mapped section.
 *
 * Reads at most @size bytes from @msec at @addr in @asid into @buffer.
 *
 * Returns the number of bytes read on success, a negative error code otherwise.
 * Returns -pte_internal, if @msec or @asid are NULL.
 * Returns -pte_invalid, if @buffer is NULL.
 * Returns -pte_nomap, if the mapped section does not contain @addr in @asid.
 */
extern int pt_msec_read(const struct pt_mapped_section *msec, uint8_t *buffer,
			uint16_t size, const struct pt_asid *asid,
			uint64_t addr);

/* Read memory from a mapped section.
 *
 * This function is similar to the above but requires the caller to map @msec.
 *
 * Returns the number of bytes read on success, a negative error code otherwise.
 * Returns -pte_internal, if @msec or @asid are NULL.
 * Returns -pte_invalid, if @buffer is NULL.
 * Returns -pte_nomap, if the mapped section does not contain @addr in @asid.
 */
extern int pt_msec_read_mapped(const struct pt_mapped_section *msec,
			       uint8_t *buffer, uint16_t size,
			       const struct pt_asid *asid, uint64_t addr);

#endif /* PT_MAPPED_SECTION_H */
