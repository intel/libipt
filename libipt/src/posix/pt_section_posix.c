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

#define _POSIX_C_SOURCE 1
#define _DARWIN_C_SOURCE 1

#include "pt_section.h"
#include "pt_section_posix.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>


int pt_section_mk_status(void **pstatus, uint64_t *psize, const char *filename)
{
	struct pt_sec_posix_status *status;
	struct stat buffer;
	int errcode;

	if (!pstatus || !psize)
		return -pte_internal;

	errcode = stat(filename, &buffer);
	if (errcode < 0)
		return errcode;

	if (buffer.st_size < 0)
		return -pte_bad_image;

	status = malloc(sizeof(*status));
	if (!status)
		return -pte_nomem;

	status->stat = buffer;

	*pstatus = status;
	*psize = buffer.st_size;

	return 0;
}

static int check_file_status(struct pt_section *section, int fd)
{
	struct pt_sec_posix_status *status;
	struct stat stat;
	int errcode;

	if (!section)
		return -pte_internal;

	errcode = fstat(fd, &stat);
	if (errcode)
		return -pte_bad_image;

	status = section->status;
	if (!status)
		return -pte_internal;

	if (stat.st_size != status->stat.st_size)
		return -pte_bad_image;

	if (stat.st_mtime != status->stat.st_mtime)
		return -pte_bad_image;

	return 0;
}

int pt_sec_posix_map(struct pt_section *section, int fd)
{
	struct pt_sec_posix_mapping *mapping;
	uint64_t offset, size, adjustment;
	uint8_t *base;

	if (!section)
		return -pte_internal;

	offset = section->offset;
	size = section->size;

	adjustment = offset % PAGE_SIZE;

	offset -= adjustment;
	size += adjustment;

	/* The section is supposed to fit into the file so we shouldn't
	 * see any overflows, here.
	 */
	if (size < section->size)
		return -pte_internal;

	base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (base == MAP_FAILED)
		return -pte_nomem;

	mapping = malloc(sizeof(*mapping));
	if (!mapping)
		goto out_map;

	mapping->base = base;
	mapping->size = size;
	mapping->begin = base + adjustment;
	mapping->end = base + size;

	section->mapping = mapping;
	section->unmap = pt_sec_posix_unmap;
	section->read = pt_sec_posix_read;

	return 0;

out_map:
	munmap(base, size);
	return -pte_nomem;
}

int pt_section_map(struct pt_section *section)
{
	const char *filename;
	int fd, errcode;

	if (!section || section->mapping)
		return -pte_internal;

	filename = section->filename;
	if (!filename)
		return -pte_internal;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return -pte_bad_image;

	errcode = check_file_status(section, fd);
	if (errcode < 0)
		goto out;

	errcode = pt_sec_posix_map(section, fd);

out:
	close(fd);
	return errcode;
}

int pt_sec_posix_unmap(struct pt_section *section)
{
	struct pt_sec_posix_mapping *mapping;

	if (!section)
		return -pte_internal;

	mapping = section->mapping;
	if (!mapping || !section->unmap || !section->read)
		return -pte_internal;

	section->mapping = NULL;
	section->unmap = NULL;
	section->read = NULL;

	munmap(mapping->base, mapping->size);
	free(mapping);

	return 0;
}

int pt_sec_posix_read(const struct pt_section *section, uint8_t *buffer,
		      uint16_t size, uint64_t offset)
{
	struct pt_sec_posix_mapping *mapping;
	const uint8_t *begin, *end;
	int bytes;

	if (!buffer || !section)
		return -pte_invalid;

	mapping = section->mapping;
	if (!mapping)
		return -pte_internal;

	begin = mapping->begin + offset;
	end = begin + size;

	if (end < begin)
		return -pte_nomap;

	if (mapping->end <= begin)
		return -pte_nomap;

	if (begin < mapping->begin)
		return -pte_nomap;

	if (mapping->end < end)
		end = mapping->end;

	bytes = (int) (end - begin);

	memcpy(buffer, begin, bytes);
	return bytes;
}
