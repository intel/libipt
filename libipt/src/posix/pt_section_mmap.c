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

#include "pt_section.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>


/* A section based on mmap. */
struct pt_section {
	/* The name of the file this was mapped from. */
	char *filename;

	/* The mmap base address. */
	uint8_t *base;

	/* The mapped memory size. */
	size_t size;

	/* The begin and end of the mapped memory. */
	const uint8_t *begin, *end;

	/* The load address of this section in virtual memory. */
	uint64_t address;
};

static char *dupstr(const char *str)
{
	char *dup;
	size_t len;

	if (!str)
		return NULL;

	len = strlen(str);
	dup = malloc(len + 1);
	if (!dup)
		return NULL;

	return strcpy(dup, str);
}

struct pt_section *pt_mk_section(const char *file, uint64_t offset,
				 uint64_t size, uint64_t addr)
{
	struct pt_section *section;
	struct stat stat;
	uint64_t fsize, adjustment;
	uint8_t *base;
	int fd, errcode;

	if (!file)
		return NULL;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return NULL;

	section = NULL;

	/* Determine the size of the file. */
	errcode = fstat(fd, &stat);
	if (errcode)
		goto out;

	/* Fail if the requested @offset lies beyond the end of @file. */
	fsize = stat.st_size;
	if (fsize <= offset)
		goto out;

	/* Truncate the requested @size to match the file size. */
	fsize -= offset;
	if (fsize < size)
		size = fsize;

	/* Mmap does not like unaligned offsets. */
	adjustment = offset % PAGE_SIZE;

	/* Adjust size and offset accordingly. */
	size += adjustment;
	offset -= adjustment;

	base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (base == MAP_FAILED)
		goto out;

	section = malloc(sizeof(*section));
	if (!section) {
		munmap(base, size);
		goto out;
	}

	section->filename = dupstr(file);
	section->base = base;
	section->size = size;
	section->begin = base + adjustment;
	section->end = base + size;
	section->address = addr;

out:
	close(fd);

	return section;
}

void pt_section_free(struct pt_section *section)
{
	if (!section)
		return;

	munmap(section->base, section->size);
	free(section->filename);
	free(section);
}

const char *pt_section_filename(const struct pt_section *section)
{
	if (!section)
		return NULL;

	return section->filename;
}

uint64_t pt_section_begin(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->address;
}

uint64_t pt_section_end(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->address + (section->end - section->begin);
}

int pt_section_read(struct pt_section *section, uint8_t *buffer, uint16_t size,
		    uint64_t addr)
{
	const uint8_t *begin, *end;

	if (!buffer || !section)
		return -pte_invalid;

	if (addr < section->address)
		return -pte_nomap;

	addr -= section->address;

	begin = section->begin + addr;
	end = begin + size;

	if (end < begin)
		return -pte_nomap;

	if (section->end <= begin)
		return -pte_nomap;

	if (section->end < end)
		size -= (end - section->end);

	memcpy(buffer, begin, size);
	return (int) size;
}
