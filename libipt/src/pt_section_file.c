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


/* A section based on file operations. */
struct pt_section {
	/* The name of the file. */
	char *filename;

	/* The FILE pointer. */
	FILE *file;

	/* The begin and end of the section as offset into @file. */
	long begin, end;

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

struct pt_section *pt_mk_section(const char *filename, uint64_t offset,
				 uint64_t size, uint64_t addr)
{
	struct pt_section *section;
	uint64_t begin, end, msize;
	long fbegin, fend, fsize;
	FILE *file;
	int errcode;

	if (!filename)
		return NULL;

	file = fopen(filename, "rb");
	if (!file)
		return NULL;

	/* Determine the size of the file. */
	errcode = fseek(file, 0, SEEK_END);
	if (errcode)
		goto out;

	fsize = ftell(file);
	if (fsize < 0)
		goto out;

	begin = offset;
	end = offset + size;
	msize = fsize;

	if (end < begin)
		goto out;

	/* Fail if the requested @offset lies beyond the end of @file. */
	if (msize <= begin)
		goto out;

	/* Truncate the requested @size to match the file size. */
	if (msize < end)
		end = msize;

	/* File operations only support long - adjust @begin and @end. */
	fbegin = (long) begin;
	fend = (long) end;

	if ((uint64_t) fbegin != begin)
		goto out;

	if ((uint64_t) fend != end)
		goto out;

	if (fend < fbegin)
		goto out;

	section = malloc(sizeof(*section));
	if (!section)
		goto out;

	section->filename = dupstr(filename);
	section->file = file;
	section->begin = fbegin;
	section->end = fend;
	section->address = addr;

	return section;

out:
	fclose(file);
	return NULL;
}

void pt_section_free(struct pt_section *section)
{
	if (!section)
		return;

	fclose(section->file);

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
	long begin, end;
	size_t read;
	int errcode;

	if (!buffer || !section)
		return -pte_invalid;

	if (addr < section->address)
		return -pte_nomap;

	addr -= section->address;
	begin = (long) addr;
	if (((uint64_t) begin) != addr)
		return -pte_nomap;

	begin += section->begin;
	end = begin + size;

	if (end < begin)
		return -pte_nomap;

	if (section->end <= begin)
		return -pte_nomap;

	errcode = fseek(section->file, begin, SEEK_SET);
	if (errcode)
		return -pte_nomap;

	read = fread(buffer, 1, size, section->file);
	return (int) read;
}
