/*
 * Copyright (c) 2013-2017, Intel Corporation
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
#include "pt_block_cache.h"

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

int pt_section_clone(struct pt_section **pclone,
		     const struct pt_section *section, uint64_t offset,
		     uint64_t size)
{
	struct pt_section *clone;
	uint64_t begin, end, sbegin, send;

	if (!pclone || !section)
		return -pte_internal;

	begin = offset;
	end = begin + size;

	sbegin = pt_section_offset(section);
	send = sbegin + pt_section_size(section);

	if (begin < sbegin || send < end)
		return -pte_internal;

	clone = pt_mk_section(pt_section_filename(section), offset, size);
	if (!clone)
		return -pte_nomem;

	*pclone = clone;
	return 0;
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
		return -pte_overflow;
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

uint64_t pt_section_offset(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->offset;
}

int pt_section_add_bcache(struct pt_section *section)
{
	uint32_t cache_size;

	if (!section || section->bcache)
		return -pte_internal;

	if (section->disable_bcache)
		return 0;

	cache_size = (uint32_t) section->size;

	/* We do not allocate a cache if it would get too big.
	 *
	 * We also do not treat failure to allocate a cache as an error.
	 * Without the cache, decode will be slower but still correct.
	 */
	if (cache_size == section->size)
		section->bcache = pt_bcache_alloc(cache_size);

	return 0;
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

	pt_bcache_free(section->bcache);
	section->bcache = NULL;

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
	uint64_t limit, space;

	if (!section)
		return -pte_internal;

	if (!section->read)
		return -pte_nomap;

	limit = section->size;
	if (limit <= offset)
		return -pte_nomap;

	/* Truncate if we try to read past the end of the section. */
	space = limit - offset;
	if (space < size)
		size = (uint16_t) space;

	return section->read(section, buffer, size, offset);
}
