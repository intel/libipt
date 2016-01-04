/*
 * Copyright (c) 2013-2016, Intel Corporation
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
#include <stdio.h>
#include <string.h>


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
				 uint64_t size)
{
	struct pt_section *section;
	uint64_t fsize;
	void *status;
	int errcode;

	errcode = pt_section_mk_status(&status, &fsize, filename);
	if (errcode < 0)
		return NULL;

	/* Fail if the requested @offset lies beyond the end of @file. */
	if (fsize <= offset)
		goto out_status;

	/* Truncate @size so the entire range lies within @file. */
	fsize -= offset;
	if (fsize < size)
		size = fsize;

	section = malloc(sizeof(*section));
	if (!section)
		goto out_status;

	memset(section, 0, sizeof(*section));

	section->filename = dupstr(filename);
	section->status = status;
	section->offset = offset;
	section->size = size;
	section->ucount = 1;

#if defined(FEATURE_THREADS)

	errcode = mtx_init(&section->lock, mtx_plain);
	if (errcode != thrd_success) {
		free(section->filename);
		free(section);
		goto out_status;
	}

#endif /* defined(FEATURE_THREADS) */

	return section;

out_status:
	free(status);
	return NULL;
}

int pt_section_lock(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

#if defined(FEATURE_THREADS)
	{
		int errcode;

		errcode = mtx_lock(&section->lock);
		if (errcode != thrd_success)
			return -pte_bad_lock;
	}
#endif /* defined(FEATURE_THREADS) */

	return 0;
}

int pt_section_unlock(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

#if defined(FEATURE_THREADS)
	{
		int errcode;

		errcode = mtx_unlock(&section->lock);
		if (errcode != thrd_success)
			return -pte_bad_lock;
	}
#endif /* defined(FEATURE_THREADS) */

	return 0;
}

static void pt_section_free(struct pt_section *section)
{
	if (!section)
		return;

#if defined(FEATURE_THREADS)

	mtx_destroy(&section->lock);

#endif /* defined(FEATURE_THREADS) */

	free(section->filename);
	free(section->status);
	free(section);
}

int pt_section_get(struct pt_section *section)
{
	uint16_t ucount;
	int errcode;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	ucount = section->ucount + 1;
	if (!ucount) {
		(void) pt_section_unlock(section);
		return -pte_internal;
	}

	section->ucount = ucount;

	return pt_section_unlock(section);
}

int pt_section_put(struct pt_section *section)
{
	uint16_t ucount, mcount;
	int errcode;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	mcount = section->mcount;
	ucount = section->ucount;
	if (ucount > 1) {
		section->ucount = ucount - 1;
		return pt_section_unlock(section);
	}

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	if (!ucount || mcount)
		return -pte_internal;

	pt_section_free(section);
	return 0;
}

const char *pt_section_filename(const struct pt_section *section)
{
	if (!section)
		return NULL;

	return section->filename;
}

uint64_t pt_section_size(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->size;
}

int pt_section_unmap(struct pt_section *section)
{
	uint16_t mcount;
	int errcode, status;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	mcount = section->mcount;

	errcode = -pte_nomap;
	if (!mcount)
		goto out_unlock;

	section->mcount = mcount -= 1;
	if (mcount)
		return pt_section_unlock(section);

	errcode = -pte_internal;
	if (!section->unmap)
		goto out_unlock;

	status = section->unmap(section);

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	return status;

out_unlock:
	(void) pt_section_unlock(section);
	return errcode;
}

int pt_section_read(const struct pt_section *section, uint8_t *buffer,
		    uint16_t size, uint64_t offset)
{
	if (!section)
		return -pte_internal;

	if (!section->read)
		return -pte_nomap;

	return section->read(section, buffer, size, offset);
}
