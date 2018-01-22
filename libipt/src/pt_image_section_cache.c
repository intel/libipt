/*
 * Copyright (c) 2016-2018, Intel Corporation
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

#include "pt_image_section_cache.h"
#include "pt_section.h"

#include "intel-pt.h"

#include <stdlib.h>


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

int pt_iscache_init(struct pt_image_section_cache *iscache, const char *name)
{
	if (!iscache)
		return -pte_internal;

	memset(iscache, 0, sizeof(*iscache));
	iscache->limit = UINT64_MAX;
	if (name) {
		iscache->name = dupstr(name);
		if (!iscache->name)
			return -pte_nomem;
	}

#if defined(FEATURE_THREADS)
	{
		int errcode;

		errcode = mtx_init(&iscache->lock, mtx_plain);
		if (errcode != thrd_success)
			return -pte_bad_lock;
	}
#endif /* defined(FEATURE_THREADS) */

	return 0;
}

void pt_iscache_fini(struct pt_image_section_cache *iscache)
{
	if (!iscache)
		return;

	(void) pt_iscache_clear(iscache);
	free(iscache->name);

#if defined(FEATURE_THREADS)

	mtx_destroy(&iscache->lock);

#endif /* defined(FEATURE_THREADS) */
}

static inline int pt_iscache_lock(struct pt_image_section_cache *iscache)
{
	if (!iscache)
		return -pte_internal;

#if defined(FEATURE_THREADS)
	{
		int errcode;

		errcode = mtx_lock(&iscache->lock);
		if (errcode != thrd_success)
			return -pte_bad_lock;
	}
#endif /* defined(FEATURE_THREADS) */

	return 0;
}

static inline int pt_iscache_unlock(struct pt_image_section_cache *iscache)
{
	if (!iscache)
		return -pte_internal;

#if defined(FEATURE_THREADS)
	{
		int errcode;

		errcode = mtx_unlock(&iscache->lock);
		if (errcode != thrd_success)
			return -pte_bad_lock;
	}
#endif /* defined(FEATURE_THREADS) */

	return 0;
}

static inline int isid_from_index(uint16_t index)
{
	return index + 1;
}

static int pt_iscache_expand(struct pt_image_section_cache *iscache)
{
	struct pt_iscache_entry *entries;
	uint16_t capacity, target;

	if (!iscache)
		return -pte_internal;

	capacity = iscache->capacity;
	target = capacity + 8;

	/* Check for overflows. */
	if (target < capacity)
		return -pte_nomem;

	entries = realloc(iscache->entries, target * sizeof(*entries));
	if (!entries)
		return -pte_nomem;

	iscache->capacity = target;
	iscache->entries = entries;
	return 0;
}

static int pt_iscache_find_locked(struct pt_image_section_cache *iscache,
				  const char *filename, uint64_t offset,
				  uint64_t size, uint64_t laddr)
{
	uint16_t idx, end;

	if (!iscache || !filename)
		return -pte_internal;

	end = iscache->size;
	for (idx = 0; idx < end; ++idx) {
		const struct pt_iscache_entry *entry;
		const struct pt_section *section;
		const char *sec_filename;
		uint64_t sec_offset, sec_size;

		entry = &iscache->entries[idx];

		/* We do not zero-initialize the array - a NULL check is
		 * pointless.
		 */
		section = entry->section;
		sec_filename = pt_section_filename(section);
		sec_offset = pt_section_offset(section);
		sec_size = pt_section_size(section);

		if (entry->laddr != laddr)
			continue;

		if (sec_offset != offset)
			continue;

		if (sec_size != size)
			continue;

		/* We should not have a section without a filename. */
		if (!sec_filename)
			return -pte_internal;

		if (strcmp(sec_filename, filename) != 0)
			continue;

		return isid_from_index(idx);
	}

	return 0;
}

static int section_match(const struct pt_section *lhs,
			 const struct pt_section *rhs)
{
	const char *lfilename, *rfilename;

	if (!lhs || !rhs)
		return -pte_internal;

	if (pt_section_offset(lhs) != pt_section_offset(rhs))
		return 0;

	if (pt_section_size(lhs) != pt_section_size(rhs))
		return 0;

	lfilename = pt_section_filename(lhs);
	rfilename = pt_section_filename(rhs);

	if (!lfilename || !rfilename)
		return -pte_internal;

	if (strcmp(lfilename, rfilename) != 0)
		return 0;

	return 1;
}

static int pt_iscache_lru_free(struct pt_iscache_lru_entry *lru)
{
	while (lru) {
		struct pt_iscache_lru_entry *trash;
		int errcode;

		trash = lru;
		lru = lru->next;

		errcode = pt_section_unmap(trash->section);
		if (errcode < 0)
			return errcode;

		free(trash);
	}

	return 0;
}

static int pt_iscache_lru_prune(struct pt_image_section_cache *iscache,
				struct pt_iscache_lru_entry **tail)
{
	struct pt_iscache_lru_entry *lru, **pnext;
	uint64_t limit, used;

	if (!iscache || !tail)
		return -pte_internal;

	limit = iscache->limit;
	used = 0ull;

	pnext = &iscache->lru;
	for (lru = *pnext; lru; pnext = &lru->next, lru = *pnext) {

		used += lru->size;
		if (used <= limit)
			continue;

		/* The cache got too big; prune it starting from @lru. */
		iscache->used = used - lru->size;
		*pnext = NULL;
		*tail = lru;

		return 0;
	}

	/* We shouldn't prune the cache unnecessarily. */
	return -pte_internal;
}

/* Add @section to the front of @iscache->lru.
 *
 * Returns a positive integer if we need to prune the cache.
 * Returns zero if we don't need to prune the cache.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_isache_lru_new(struct pt_image_section_cache *iscache,
			     struct pt_section *section)
{
	struct pt_iscache_lru_entry *lru;
	uint64_t memsize, used, total, limit;
	int errcode;

	if (!iscache)
		return -pte_internal;

	errcode = pt_section_memsize(section, &memsize);
	if (errcode < 0)
		return errcode;

	/* Don't try to add the section if it is too big.  We'd prune it again
	 * together with all other sections in our cache.
	 */
	limit = iscache->limit;
	if (limit < memsize)
		return 0;

	errcode = pt_section_map_share(section);
	if (errcode < 0)
		return errcode;

	lru = malloc(sizeof(*lru));
	if (!lru) {
		(void) pt_section_unmap(section);
		return -pte_nomem;
	}

	lru->section = section;
	lru->size = memsize;

	lru->next = iscache->lru;
	iscache->lru = lru;

	used = iscache->used;
	total = used + memsize;
	if (total < used || total < memsize)
		return -pte_overflow;

	iscache->used = total;

	return (limit < total) ? 1 : 0;
}

/* Add or move @section to the front of @iscache->lru.
 *
 * Returns a positive integer if we need to prune the cache.
 * Returns zero if we don't need to prune the cache.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_iscache_lru_add(struct pt_image_section_cache *iscache,
			      struct pt_section *section)
{
	struct pt_iscache_lru_entry *lru, **pnext;

	if (!iscache)
		return -pte_internal;

	pnext = &iscache->lru;
	for (lru = *pnext; lru; pnext = &lru->next, lru = *pnext) {

		if (lru->section != section)
			continue;

		/* We found it in the cache.  Move it to the front. */
		*pnext = lru->next;
		lru->next = iscache->lru;
		iscache->lru = lru;

		return 0;
	}

	/* We didn't find it in the cache.  Add it. */
	return pt_isache_lru_new(iscache, section);
}


/* Add or move @section to the front of @iscache->lru and update its size.
 *
 * Returns a positive integer if we need to prune the cache.
 * Returns zero if we don't need to prune the cache.
 * Returns a negative pt_error_code otherwise.
 */
static int pt_iscache_lru_resize(struct pt_image_section_cache *iscache,
				 struct pt_section *section, uint64_t memsize)
{
	struct pt_iscache_lru_entry *lru;
	uint64_t oldsize, used;
	int status;

	if (!iscache)
		return -pte_internal;

	status = pt_iscache_lru_add(iscache, section);
	if (status < 0)
		return status;

	lru = iscache->lru;
	if (!lru) {
		if (status)
			return -pte_internal;
		return 0;
	}

	/* If @section is cached, it must be first.
	 *
	 * We may choose not to cache it, though, e.g. if it is too big.
	 */
	if (lru->section != section) {
		if (iscache->limit < memsize)
			return 0;

		return -pte_internal;
	}

	oldsize = lru->size;
	lru->size = memsize;

	/* If we need to prune anyway, we're done. */
	if (status)
		return status;

	used = iscache->used;
	used -= oldsize;
	used += memsize;

	iscache->used = used;

	return (iscache->limit < used) ? 1 : 0;
}


int pt_iscache_add(struct pt_image_section_cache *iscache,
		   struct pt_section *section, uint64_t laddr)
{
	uint16_t idx, end;
	int errcode;

	if (!iscache || !section)
		return -pte_internal;

	/* We must have a filename for @section. */
	if (!pt_section_filename(section))
		return -pte_internal;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	end = iscache->size;
	for (idx = 0; idx < end; ++idx) {
		const struct pt_iscache_entry *entry;
		struct pt_section *sec;

		entry = &iscache->entries[idx];

		/* We do not zero-initialize the array - a NULL check is
		 * pointless.
		 */
		sec = entry->section;

		errcode = section_match(section, sec);
		if (errcode <= 0) {
			if (errcode < 0)
				goto out_unlock;

			continue;
		}

		/* Use the cached section instead of the argument section.
		 *
		 * We'll be able to drop the argument section in this case and
		 * only keep one copy around and, more importantly, mapped.
		 */
		section = sec;

		/* If we also find a matching load address, we're done. */
		if (laddr == entry->laddr)
			break;
	}

	/* If we have not found a matching entry, add one. */
	if (idx == end) {
		struct pt_iscache_entry *entry;

		/* Expand the cache, if necessary. */
		if (iscache->capacity <= iscache->size) {
			/* We must never exceed the capacity. */
			if (iscache->capacity < iscache->size) {
				errcode = -pte_internal;
				goto out_unlock;
			}

			errcode = pt_iscache_expand(iscache);
			if (errcode < 0)
				goto out_unlock;

			/* Make sure it is big enough, now. */
			if (iscache->capacity <= iscache->size) {
				errcode = -pte_internal;
				goto out_unlock;
			}
		}

		errcode = pt_section_attach(section, iscache);
		if (errcode < 0)
			goto out_unlock;

		idx = iscache->size++;

		entry = &iscache->entries[idx];
		entry->section = section;
		entry->laddr = laddr;
	}

	errcode = pt_iscache_unlock(iscache);
	if (errcode < 0)
		return errcode;

	return isid_from_index(idx);

 out_unlock:
	(void) pt_iscache_unlock(iscache);
	return errcode;
}

int pt_iscache_find(struct pt_image_section_cache *iscache,
		    const char *filename, uint64_t offset, uint64_t size,
		    uint64_t laddr)
{
	int errcode, isid;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	isid = pt_iscache_find_locked(iscache, filename, offset, size, laddr);

	errcode = pt_iscache_unlock(iscache);
	if (errcode < 0)
		return errcode;

	return isid;
}

int pt_iscache_lookup(struct pt_image_section_cache *iscache,
		      struct pt_section **section, uint64_t *laddr, int isid)
{
	uint16_t index;
	int errcode, status;

	if (!iscache || !section || !laddr)
		return -pte_internal;

	if (isid <= 0)
		return -pte_bad_image;

	isid -= 1;
	if (isid > UINT16_MAX)
		return -pte_internal;

	index = (uint16_t) isid;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	if (iscache->size <= index)
		status = -pte_bad_image;
	else {
		const struct pt_iscache_entry *entry;

		entry = &iscache->entries[index];
		*section = entry->section;
		*laddr = entry->laddr;

		status = pt_section_get(*section);
	}

	errcode = pt_iscache_unlock(iscache);
	if (errcode < 0)
		return errcode;

	return status;
}

int pt_iscache_clear(struct pt_image_section_cache *iscache)
{
	struct pt_iscache_lru_entry *lru;
	struct pt_iscache_entry *entries;
	uint16_t idx, end;
	int errcode;

	if (!iscache)
		return -pte_internal;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	entries = iscache->entries;
	end = iscache->size;
	lru = iscache->lru;

	iscache->entries = NULL;
	iscache->capacity = 0;
	iscache->size = 0;
	iscache->lru = NULL;
	iscache->used = 0ull;

	errcode = pt_iscache_unlock(iscache);
	if (errcode < 0)
		return errcode;

	errcode = pt_iscache_lru_free(lru);
	if (errcode < 0)
		return errcode;

	for (idx = 0; idx < end; ++idx) {
		const struct pt_iscache_entry *entry;

		entry = &entries[idx];

		/* We do not zero-initialize the array - a NULL check is
		 * pointless.
		 */
		errcode = pt_section_detach(entry->section, iscache);
		if (errcode < 0)
			return errcode;
	}

	free(entries);
	return 0;
}

struct pt_image_section_cache *pt_iscache_alloc(const char *name)
{
	struct pt_image_section_cache *iscache;

	iscache = malloc(sizeof(*iscache));
	if (iscache)
		pt_iscache_init(iscache, name);

	return iscache;
}

void pt_iscache_free(struct pt_image_section_cache *iscache)
{
	if (!iscache)
		return;

	pt_iscache_fini(iscache);
	free(iscache);
}

int pt_iscache_set_limit(struct pt_image_section_cache *iscache, uint64_t limit)
{
	struct pt_iscache_lru_entry *tail;
	int errcode, status;

	if (!iscache)
		return -pte_invalid;

	status = 0;
	tail = NULL;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	iscache->limit = limit;
	if (limit < iscache->used)
		status = pt_iscache_lru_prune(iscache, &tail);

	errcode = pt_iscache_unlock(iscache);

	if (errcode < 0 || status < 0)
		return (status < 0) ? status : errcode;

	return pt_iscache_lru_free(tail);
}

const char *pt_iscache_name(const struct pt_image_section_cache *iscache)
{
	if (!iscache)
		return NULL;

	return iscache->name;
}

int pt_iscache_add_file(struct pt_image_section_cache *iscache,
			const char *filename, uint64_t offset, uint64_t size,
			uint64_t vaddr)
{
	struct pt_section *section;
	int isid, errcode;

	if (!iscache || !filename)
		return -pte_invalid;

	isid = pt_iscache_find(iscache, filename, offset, size, vaddr);
	if (isid != 0)
		return isid;

	section = pt_mk_section(filename, offset, size);
	if (!section)
		return -pte_invalid;

	isid = pt_iscache_add(iscache, section, vaddr);

	/* We grab a reference when we add the section.  Drop the one we
	 * obtained when creating the section.
	 */
	errcode = pt_section_put(section);
	if (errcode < 0)
		return errcode;

	return isid;
}


int pt_iscache_read(struct pt_image_section_cache *iscache, uint8_t *buffer,
		    uint64_t size, int isid, uint64_t vaddr)
{
	struct pt_section *section;
	uint64_t laddr;
	int errcode, status;

	if (!iscache || !buffer || !size)
		return -pte_invalid;

	errcode = pt_iscache_lookup(iscache, &section, &laddr, isid);
	if (errcode < 0)
		return errcode;

	if (vaddr < laddr) {
		(void) pt_section_put(section);
		return -pte_nomap;
	}

	vaddr -= laddr;

	errcode = pt_section_map(section);
	if (errcode < 0) {
		(void) pt_section_put(section);
		return errcode;
	}

	/* We truncate the read if it gets too big.  The user is expected to
	 * issue further reads for the remaining part.
	 */
	if (UINT16_MAX < size)
		size = UINT16_MAX;

	status = pt_section_read(section, buffer, (uint16_t) size, vaddr);

	errcode = pt_section_unmap(section);
	if (errcode < 0) {
		(void) pt_section_put(section);
		return errcode;
	}

	errcode = pt_section_put(section);
	if (errcode < 0)
		return errcode;

	return status;
}

int pt_iscache_notify_map(struct pt_image_section_cache *iscache,
			  struct pt_section *section)
{
	struct pt_iscache_lru_entry *tail;
	int errcode, status;

	tail = NULL;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	status = pt_iscache_lru_add(iscache, section);
	if (status > 0)
		status = pt_iscache_lru_prune(iscache, &tail);

	errcode = pt_iscache_unlock(iscache);

	if (errcode < 0 || status < 0)
		return (status < 0) ? status : errcode;

	return pt_iscache_lru_free(tail);
}

int pt_iscache_notify_resize(struct pt_image_section_cache *iscache,
			     struct pt_section *section, uint64_t memsize)
{
	struct pt_iscache_lru_entry *tail;
	int errcode, status;

	tail = NULL;

	errcode = pt_iscache_lock(iscache);
	if (errcode < 0)
		return errcode;

	status = pt_iscache_lru_resize(iscache, section, memsize);
	if (status > 0)
		status = pt_iscache_lru_prune(iscache, &tail);

	errcode = pt_iscache_unlock(iscache);

	if (errcode < 0 || status < 0)
		return (status < 0) ? status : errcode;

	return pt_iscache_lru_free(tail);
}
