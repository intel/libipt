/*
 * Copyright (c) 2015, Intel Corporation
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

#include <stdio.h>


static uint64_t file_size(const char *filename)
{
	FILE *file;
	long fsize;
	int errcode;

	if (!filename)
		return 0ull;

	file = fopen(filename, "rb");
	if (!file)
		return 0ull;

	/* Determine the size of the file. */
	errcode = fseek(file, 0, SEEK_END);
	if (errcode)
		return 0ull;

	fsize = ftell(file);
	if (fsize < 0)
		return 0ull;

	return (uint64_t) fsize;
}

int pt_section_mk_status(void **pstatus, uint64_t *psize, const char *filename)
{
	uint64_t size, *status;

	if (!pstatus || !psize || !filename)
		return -pte_internal;

	size = file_size(filename);
	if (!size)
		return -pte_bad_image;

	status = malloc(sizeof(size));
	if (!status)
		return -pte_nomem;

	*status = size;
	*pstatus = status;
	*psize = size;

	return 0;
}

int pt_section_map(struct pt_section *section)
{
	const char *filename;
	uint64_t size, *status;
	FILE *file;
	int errcode;

	if (!section || section->mapping)
		return -pte_internal;

	filename = section->filename;
	if (!filename)
		return -pte_internal;

	status = section->status;
	if (!status)
		return -pte_internal;

	file = fopen(filename, "rb+");
	if (!file)
		return -pte_bad_image;

	size = file_size(filename);
	if (size != *status) {
		errcode = -pte_bad_image;
		goto err_file;
	}

	errcode = pt_sec_file_map(section, file);
	if (errcode < 0)
		goto err_file;

	/* We need to keep the file open on success.  It will be closed when
	 * the section is unmapped.
	 */
	return 0;

err_file:
	fclose(file);
	return errcode;
}
