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

#ifndef __LOAD_H__
#define __LOAD_H__

#include <stdint.h>
#include <stddef.h>


/* A load map for an ELF file. */
struct load_map {
	/* The next entry. */
	struct load_map *next;

	/* The memory this segment has been loaded into. */
	uint8_t *memory;

	/* The load address of this segment in the ELF. */
	uint64_t address;

	/* The size of the segment in bytes. */
	size_t size;

	/* The name of the file (optional). */
	char *file;
};

/* Load an ELF file.
 *
 * Maps ELF LOAD segments into memory. Extends @map to describe the layout.
 *
 * If @addr is not 0, it specifies the load address of all segments assuming a
 * contiguous layout.
 *
 * Does not load dependent files.
 * Does not support dynamic relocations.
 *
 * Successfully loaded segments are not unloaded in case of errors.
 *
 * Returns 0 on success.
 * Returns a negative error code on failure.
 * Returns -ENOMEM if not enough memory can be allocated to hold all segments.
 * Returns -EOPNOTSUP if the ELF file contains dependencies.
 * Returns -EOPNOTSUP if the ELF file contains dynamic relocations.
 */
extern int load_elf(const char *file, struct load_map **map, uint64_t addr);

/* Load a raw memory dump.
 *
 * Maps the memory dump into memory at @addr. Extends @map to describe the
 * layout.
 *
 *
 * Returns 0 on success.
 * Returns a negative error code on failure.
 * Returns -ENOMEM if not enough memory can be allocated to hold all segments.
 */
extern int load_raw(const char *file, struct load_map **map, uint64_t addr);

/* Unload previously loaded memory.
 *
 * After unloading, @map must be used.
 */
extern void unload(struct load_map *map);

/* Translate a target address into a pointer into the mapped ELF image.
 *
 * If space is not NULL, returns the number of bytes available in the respective
 * segment in @space.
 *
 * Returns a non-null pointer to the translated address on success.
 * Returns NULL if the memory is not mapped.
 */
extern uint8_t *translate(struct load_map *, uint64_t, uint64_t *space);

#endif /* __LOAD_H__ */
