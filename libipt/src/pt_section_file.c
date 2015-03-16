/*
 * Copyright (c) 2013-2015, Intel Corporation
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
#include "pt_section_file.h"

#include "intel-pt.h"

#include <stdlib.h>


int pt_sec_file_map(struct pt_section *section, FILE *file)
{
	struct pt_sec_file_mapping *mapping;
	uint64_t offset, size;
	long begin, end, fsize;
	int errcode;

	if (!section)
		return -pte_internal;

	mapping = section->mapping;
	if (mapping)
		return -pte_internal;

	offset = section->offset;
	size = section->size;

	begin = (long) offset;
	end = begin + (long) size;

	/* Check for overflows. */
	if ((uint64_t) begin != offset)
		return -pte_bad_image;

	if ((uint64_t) end != (offset + size))
		return -pte_bad_image;

	if (end < begin)
		return -pte_bad_image;

	/* Validate that the section lies within the file. */
	errcode = fseek(file, 0, SEEK_END);
	if (errcode)
		return -pte_bad_image;

	fsize = ftell(file);
	if (fsize < 0)
		return -pte_bad_image;

	if (fsize < end)
		return -pte_bad_image;

	mapping = malloc(sizeof(*mapping));
	if (!mapping)
		return -pte_nomem;

	mapping->file = file;
	mapping->begin = begin;
	mapping->end = end;

	section->mapping = mapping;
	section->unmap = pt_sec_file_unmap;
	section->read = pt_sec_file_read;

	return 0;
}

int pt_sec_file_unmap(struct pt_section *section)
{
	struct pt_sec_file_mapping *mapping;

	if (!section)
		return -pte_internal;

	mapping = section->mapping;

	if (!mapping || !section->unmap || !section->read)
		return -pte_internal;

	section->mapping = NULL;
	section->unmap = NULL;
	section->read = NULL;

	fclose(mapping->file);
	free(mapping);

	return 0;
}

int pt_sec_file_read(const struct pt_section *section, uint8_t *buffer,
		     uint16_t size, uint64_t offset)
{
	struct pt_sec_file_mapping *mapping;
	FILE *file;
	long begin, end, fbegin, fend;
	size_t read;
	int errcode;

	if (!buffer || !section)
		return -pte_invalid;

	mapping = section->mapping;
	if (!mapping)
		return -pte_internal;

	file = mapping->file;
	begin = mapping->begin;
	end = mapping->end;

	fbegin = (long) offset;
	if (((uint64_t) fbegin) != offset)
		return -pte_nomap;

	fbegin += begin;
	fend = fbegin + size;

	if (fend < fbegin)
		return -pte_nomap;

	if (end <= fbegin)
		return -pte_nomap;

	if (fbegin < begin)
		return -pte_nomap;

	errcode = fseek(file, fbegin, SEEK_SET);
	if (errcode)
		return -pte_nomap;

	read = fread(buffer, 1, size, file);
	return (int) read;
}
