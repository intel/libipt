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

#include "pt_image.h"
#include "pt_section.h"
#include "pt_asid.h"
#include "pt_image_section_cache.h"

#include <stdlib.h>
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

static struct pt_section_list *pt_mk_section_list(struct pt_section *section,
						  const struct pt_asid *asid,
						  uint64_t vaddr, int isid)
{
	struct pt_section_list *list;
	int errcode;

	list = malloc(sizeof(*list));
	if (!list)
		return NULL;

	memset(list, 0, sizeof(*list));

	errcode = pt_section_get(section);
	if (errcode < 0)
		goto out_mem;

	pt_msec_init(&list->section, section, asid, vaddr);
	list->isid = isid;

	return list;

out_mem:
	free(list);
	return NULL;
}

static void pt_section_list_free(struct pt_section_list *list)
{
	if (!list)
		return;

	if (list->mapped)
		pt_section_unmap(list->section.section);
	pt_section_put(list->section.section);
	pt_msec_fini(&list->section);
	free(list);
}

static void pt_section_list_free_tail(struct pt_section_list *list)
{
	while (list) {
		struct pt_section_list *trash;

		trash = list;
		list = list->next;

		pt_section_list_free(trash);
	}
}

void pt_image_init(struct pt_image *image, const char *name)
{
	if (!image)
		return;

	memset(image, 0, sizeof(*image));

	image->name = dupstr(name);
	image->cache = 10;
}

void pt_image_fini(struct pt_image *image)
{
	if (!image)
		return;

	pt_section_list_free_tail(image->sections);
	free(image->name);

	memset(image, 0, sizeof(*image));
}

struct pt_image *pt_image_alloc(const char *name)
{
	struct pt_image *image;

	image = malloc(sizeof(*image));
	if (image)
		pt_image_init(image, name);

	return image;
}

void pt_image_free(struct pt_image *image)
{
	pt_image_fini(image);
	free(image);
}

const char *pt_image_name(const struct pt_image *image)
{
	if (!image)
		return NULL;

	return image->name;
}

static int pt_image_clone(struct pt_section_list **list,
			  const struct pt_mapped_section *msec,
			  uint64_t begin, uint64_t end, int isid)
{
	const struct pt_asid *masid;
	struct pt_section_list *next;
	struct pt_section *section, *sec;
	uint64_t mbegin, sbegin, offset, size;
	int errcode;

	if (!list || !msec)
		return -pte_internal;

	sec = pt_msec_section(msec);
	masid = pt_msec_asid(msec);
	mbegin = pt_msec_begin(msec);
	sbegin = pt_section_offset(sec);

	if (end <= begin)
		return -pte_internal;

	if (begin < mbegin)
		return -pte_internal;

	offset = begin - mbegin;
	size = end - begin;

	errcode = pt_section_clone(&section, sec, sbegin + offset, size);
	if (errcode < 0)
		return errcode;

	next = pt_mk_section_list(section, masid, begin, isid);
	if (!next) {
		(void) pt_section_put(section);

		return -pte_nomem;
	}

	/* The image list got its own reference; let's drop ours. */
	errcode = pt_section_put(section);
	if (errcode < 0) {
		pt_section_list_free(next);

		return errcode;
	}

	/* Add the new section. */
	next->next = *list;
	*list = next;

	return 0;
}

int pt_image_add(struct pt_image *image, struct pt_section *section,
		 const struct pt_asid *asid, uint64_t vaddr, int isid)
{
	struct pt_section_list **list, *next, *removed;
	uint64_t begin, end;
	int errcode;

	if (!image || !section)
		return -pte_internal;

	next = pt_mk_section_list(section, asid, vaddr, isid);
	if (!next)
		return -pte_nomem;

	removed = NULL;
	errcode = 0;

	begin = vaddr;
	end = begin + pt_section_size(section);

	/* Check for overlaps while we move to the end of the list. */
	list = &(image->sections);
	while (*list) {
		const struct pt_mapped_section *msec;
		const struct pt_asid *masid;
		struct pt_section_list *current;
		struct pt_section *lsec;
		uint64_t lbegin, lend;

		current = *list;
		msec = &current->section;
		masid = pt_msec_asid(msec);

		errcode = pt_asid_match(masid, asid);
		if (errcode < 0)
			break;

		if (!errcode) {
			list = &((*list)->next);
			continue;
		}

		lbegin = pt_msec_begin(msec);
		lend = pt_msec_end(msec);

		if ((end <= lbegin) || (lend <= begin)) {
			list = &((*list)->next);
			continue;
		}

		/* The new section overlaps with @msec's section. */
		lsec = pt_msec_section(msec);

		/* We remove @msec and insert new sections for the remaining
		 * parts, if any.  Those new sections are not mapped initially
		 * and need to be added to the end of the section list.
		 */
		*list = current->next;

		/* Keep a list of removed sections so we can re-add them in case
		 * of errors.
		 */
		current->next = removed;
		removed = current;

		/* Unmap the removed section.  If we need to re-add it, it will
		 * be moved to the end of the section list where the unmapped
		 * sections are.
		 */
		if (current->mapped) {
			pt_section_unmap(lsec);
			current->mapped = 0;
		}

		/* Add a section covering the remaining bytes at the front.
		 *
		 * We preserve the section identifier to indicate that the new
		 * section originated from the original section.
		 */
		if (lbegin < begin) {
			errcode = pt_image_clone(&next, msec, lbegin, begin,
						 current->isid);
			if (errcode < 0)
				break;
		}

		/* Add a section covering the remaining bytes at the back.
		 *
		 * We preserve the section identifier to indicate that the new
		 * section originated from the original section.
		 */
		if (end < lend) {
			errcode = pt_image_clone(&next, msec, end, lend,
						 current->isid);
			if (errcode < 0)
				break;
		}
	}

	if (errcode < 0) {
		pt_section_list_free_tail(next);

		/* Re-add removed sections to the tail of the section list. */
		for (; *list; list = &((*list)->next))
			;

		*list = removed;
		return errcode;
	}

	pt_section_list_free_tail(removed);

	*list = next;
	return 0;
}

int pt_image_remove(struct pt_image *image, struct pt_section *section,
		    const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_section_list **list;

	if (!image || !section)
		return -pte_internal;

	for (list = &image->sections; *list; list = &((*list)->next)) {
		struct pt_mapped_section *msec;
		const struct pt_section *sec;
		const struct pt_asid *masid;
		struct pt_section_list *trash;
		uint64_t begin;
		int errcode;

		trash = *list;
		msec = &trash->section;
		masid = pt_msec_asid(msec);

		errcode = pt_asid_match(masid, asid);
		if (errcode < 0)
			return errcode;

		if (!errcode)
			continue;

		begin = pt_msec_begin(msec);
		sec = pt_msec_section(msec);
		if (sec == section && begin == vaddr) {
			*list = trash->next;
			pt_section_list_free(trash);

			return 0;
		}
	}

	return -pte_bad_image;
}

int pt_image_add_file(struct pt_image *image, const char *filename,
		      uint64_t offset, uint64_t size,
		      const struct pt_asid *uasid, uint64_t vaddr)
{
	struct pt_section *section;
	struct pt_asid asid;
	int errcode;

	if (!image || !filename)
		return -pte_invalid;

	errcode = pt_asid_from_user(&asid, uasid);
	if (errcode < 0)
		return errcode;

	section = pt_mk_section(filename, offset, size);
	if (!section)
		return -pte_invalid;

	errcode = pt_image_add(image, section, &asid, vaddr, 0);
	if (errcode < 0) {
		(void) pt_section_put(section);
		return errcode;
	}

	/* The image list got its own reference; let's drop ours. */
	errcode = pt_section_put(section);
	if (errcode < 0)
		return errcode;

	return 0;
}

int pt_image_copy(struct pt_image *image, const struct pt_image *src)
{
	struct pt_section_list *list;
	int ignored;

	if (!image || !src)
		return -pte_invalid;

	/* There is nothing to do if we copy an image to itself.
	 *
	 * Besides, pt_image_add() may move sections around, which would
	 * interfere with our section iteration.
	 */
	if (image == src)
		return 0;

	ignored = 0;
	for (list = src->sections; list; list = list->next) {
		int errcode;

		errcode = pt_image_add(image, list->section.section,
				       &list->section.asid,
				       list->section.vaddr,
				       list->isid);
		if (errcode < 0)
			ignored += 1;
	}

	return ignored;
}

int pt_image_remove_by_filename(struct pt_image *image, const char *filename,
				const struct pt_asid *uasid)
{
	struct pt_section_list **list;
	struct pt_asid asid;
	int errcode, removed;

	if (!image || !filename)
		return -pte_invalid;

	errcode = pt_asid_from_user(&asid, uasid);
	if (errcode < 0)
		return errcode;

	removed = 0;
	for (list = &image->sections; *list;) {
		struct pt_mapped_section *msec;
		const struct pt_section *sec;
		const struct pt_asid *masid;
		struct pt_section_list *trash;
		const char *tname;

		trash = *list;
		msec = &trash->section;
		masid = pt_msec_asid(msec);

		errcode = pt_asid_match(masid, &asid);
		if (errcode < 0)
			return errcode;

		if (!errcode) {
			list = &trash->next;
			continue;
		}

		sec = pt_msec_section(msec);
		tname = pt_section_filename(sec);

		if (tname && (strcmp(tname, filename) == 0)) {
			*list = trash->next;
			pt_section_list_free(trash);

			removed += 1;
		} else
			list = &trash->next;
	}

	return removed;
}

int pt_image_remove_by_asid(struct pt_image *image,
			    const struct pt_asid *uasid)
{
	struct pt_section_list **list;
	struct pt_asid asid;
	int errcode, removed;

	if (!image)
		return -pte_invalid;

	errcode = pt_asid_from_user(&asid, uasid);
	if (errcode < 0)
		return errcode;

	removed = 0;
	for (list = &image->sections; *list;) {
		struct pt_mapped_section *msec;
		const struct pt_asid *masid;
		struct pt_section_list *trash;

		trash = *list;
		msec = &trash->section;
		masid = pt_msec_asid(msec);

		errcode = pt_asid_match(masid, &asid);
		if (errcode < 0)
			return errcode;

		if (!errcode) {
			list = &trash->next;
			continue;
		}

		*list = trash->next;
		pt_section_list_free(trash);

		removed += 1;
	}

	return removed;
}

int pt_image_set_callback(struct pt_image *image,
			  read_memory_callback_t *callback, void *context)
{
	if (!image)
		return -pte_invalid;

	image->readmem.callback = callback;
	image->readmem.context = context;

	return 0;
}

static int pt_image_prune_cache(struct pt_image *image)
{
	struct pt_section_list *list;
	uint16_t cache, mapped;
	int status;

	if (!image)
		return -pte_internal;

	cache = image->cache;
	status = 0;
	mapped = 0;
	for (list = image->sections; list; list = list->next) {
		int errcode;

		/* Let's traverse the entire list.  It isn't very long and
		 * this allows us to fix up any previous unmap errors.
		 */
		if (!list->mapped)
			continue;

		mapped += 1;
		if (mapped <= cache)
			continue;

		errcode = pt_section_unmap(list->section.section);
		if (errcode < 0) {
			status = errcode;
			continue;
		}

		list->mapped = 0;
		mapped -= 1;
	}

	image->mapped = mapped;
	return status;
}

static int pt_image_read_callback(struct pt_image *image, int *isid,
				  uint8_t *buffer, uint16_t size,
				  const struct pt_asid *asid, uint64_t addr)
{
	read_memory_callback_t *callback;

	if (!image || !isid)
		return -pte_internal;

	callback = image->readmem.callback;
	if (!callback)
		return -pte_nomap;

	*isid = 0;

	return callback(buffer, size, asid, addr, image->readmem.context);
}

/* Check whether a mapped section contains an address.
 *
 * Returns zero if @msec contains @vaddr.
 * Returns a negative error code otherwise.
 * Returns -pte_nomap if @msec does not contain @vaddr.
 */
static inline int pt_image_check_msec(const struct pt_mapped_section *msec,
				      const struct pt_asid *asid,
				      uint64_t vaddr)
{
	const struct pt_asid *masid;
	uint64_t begin, end;
	int errcode;

	if (!msec)
		return -pte_internal;

	begin = pt_msec_begin(msec);
	end = pt_msec_end(msec);
	if (vaddr < begin || end <= vaddr)
		return -pte_nomap;

	masid = pt_msec_asid(msec);
	errcode = pt_asid_match(masid, asid);
	if (errcode <= 0) {
		if (!errcode)
			errcode = -pte_nomap;

		return errcode;
	}

	return 0;
}

/* Read memory from a mapped section.
 *
 * @msec's section must be mapped.
 *
 * Returns the number of bytes read on success.
 * Returns a negative error code otherwise.
 */
static int pt_image_read_msec(uint8_t *buffer, uint16_t size,
			      const struct pt_mapped_section *msec,
			      uint64_t addr)
{
	struct pt_section *section;
	uint64_t offset;

	if (!msec)
		return -pte_internal;

	section = pt_msec_section(msec);
	offset = pt_msec_unmap(msec, addr);

	return pt_section_read(section, buffer, size, offset);
}

/* Find the section containing a given address in a given address space.
 *
 * On success, the found section is moved to the front of the section list.
 * If caching is enabled, maps the section.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int pt_image_fetch_section(struct pt_image *image,
				  const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_section_list **start, **list;

	if (!image)
		return -pte_internal;

	start = &image->sections;
	for (list = start; *list;) {
		struct pt_mapped_section *msec;
		struct pt_section_list *elem;
		int errcode;

		elem = *list;
		msec = &elem->section;

		errcode = pt_image_check_msec(msec, asid, vaddr);
		if (errcode < 0) {
			if (errcode != -pte_nomap)
				return errcode;

			list = &elem->next;
			continue;
		}

		/* Move the section to the front if it isn't already. */
		if (list != start) {
			*list = elem->next;
			elem->next = *start;
			*start = elem;
		}

		/* Map the section if it isn't already - provided we do cache
		 * recently used sections.
		 */
		if (!elem->mapped) {
			uint16_t cache, already;

			already = image->mapped;
			cache = image->cache;
			if (cache) {
				struct pt_section *section;

				section = pt_msec_section(msec);

				errcode = pt_section_map(section);
				if (errcode < 0)
					return errcode;

				elem->mapped = 1;

				already += 1;
				image->mapped = already;

				if (cache < already)
					return pt_image_prune_cache(image);
			}
		}

		return 0;
	}

	return -pte_nomap;
}

static int pt_image_read_cold(struct pt_image *image, int *isid,
			      uint8_t *buffer, uint16_t size,
			      const struct pt_asid *asid, uint64_t addr)
{
	struct pt_mapped_section *msec;
	struct pt_section_list *section;
	int errcode;

	if (!image || !isid)
		return -pte_internal;

	errcode = pt_image_fetch_section(image, asid, addr);
	if (errcode < 0) {
		if (errcode != -pte_nomap)
			return errcode;
	}

	section = image->sections;
	if (!section)
		return pt_image_read_callback(image, isid, buffer, size, asid,
					      addr);

	msec = &section->section;

	errcode = pt_image_check_msec(msec, asid, addr);
	if (errcode < 0) {
		if (errcode != -pte_nomap)
			return errcode;

		return pt_image_read_callback(image, isid, buffer, size, asid,
					      addr);
	}

	*isid = section->isid;

	if (section->mapped)
		return pt_image_read_msec(buffer, size, msec, addr);
	else {
		struct pt_section *sec;
		int status;

		sec = pt_msec_section(msec);

		errcode = pt_section_map(sec);
		if (errcode < 0)
			return errcode;

		status = pt_image_read_msec(buffer, size, msec, addr);

		errcode = pt_section_unmap(sec);
		if (errcode < 0)
			return errcode;

		return status;
	}
}


int pt_image_read(struct pt_image *image, int *isid, uint8_t *buffer,
		  uint16_t size, const struct pt_asid *asid, uint64_t addr)
{
	struct pt_mapped_section *msec;
	struct pt_section_list *section;
	int errcode;

	if (!image || !isid)
		return -pte_internal;

	section = image->sections;
	if (!section)
		return pt_image_read_callback(image, isid, buffer, size, asid,
					      addr);

	if (!section->mapped)
		return pt_image_read_cold(image, isid, buffer, size, asid,
					  addr);

	msec = &section->section;

	errcode = pt_image_check_msec(msec, asid, addr);
	if (errcode < 0) {
		if (errcode != -pte_nomap)
			return errcode;

		return pt_image_read_cold(image, isid, buffer, size, asid,
					  addr);
	}

	*isid = section->isid;

	return pt_image_read_msec(buffer, size, msec, addr);
}

int pt_image_add_cached(struct pt_image *image,
			struct pt_image_section_cache *iscache, int isid,
			const struct pt_asid *uasid)
{
	struct pt_section *section;
	struct pt_asid asid;
	uint64_t vaddr;
	int errcode, status;

	if (!image || !iscache)
		return -pte_invalid;

	errcode = pt_iscache_lookup(iscache, &section, &vaddr, isid);
	if (errcode < 0)
		return errcode;

	errcode = pt_asid_from_user(&asid, uasid);
	if (errcode < 0)
		return errcode;

	status = pt_image_add(image, section, &asid, vaddr, isid);

	/* We grab a reference when we add the section.  Drop the one we
	 * obtained from cache lookup.
	 */
	errcode = pt_section_put(section);
	if (errcode < 0)
		return errcode;

	return status;
}

static int pt_image_find_cold(struct pt_image *image,
			      struct pt_section **psection, uint64_t *laddr,
			      const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_mapped_section *msec;
	struct pt_section_list *slist;
	struct pt_section *section;
	int errcode;

	if (!image || !psection || !laddr)
		return -pte_internal;

	errcode = pt_image_fetch_section(image, asid, vaddr);
	if (errcode < 0)
		return errcode;

	slist = image->sections;
	if (!slist)
		return -pte_nomap;

	msec = &slist->section;

	errcode = pt_image_check_msec(msec, asid, vaddr);
	if (errcode < 0)
		return errcode;

	section = pt_msec_section(msec);

	errcode = pt_section_get(section);
	if (errcode < 0)
		return errcode;

	*psection = section;
	*laddr = pt_msec_begin(msec);

	return slist->isid;
}

int pt_image_find(struct pt_image *image, struct pt_section **psection,
		  uint64_t *laddr, const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_mapped_section *msec;
	struct pt_section_list *slist;
	struct pt_section *section;
	int errcode;

	if (!image || !psection || !laddr)
		return -pte_internal;

	slist = image->sections;
	if (!slist)
		return -pte_nomap;

	if (!slist->mapped)
		return pt_image_find_cold(image, psection, laddr, asid, vaddr);

	msec = &slist->section;

	errcode = pt_image_check_msec(msec, asid, vaddr);
	if (errcode < 0) {
		if (errcode != -pte_nomap)
			return errcode;

		return pt_image_find_cold(image, psection, laddr, asid, vaddr);
	}

	section = pt_msec_section(msec);

	errcode = pt_section_get(section);
	if (errcode < 0)
		return errcode;

	*psection = section;
	*laddr = pt_msec_begin(msec);

	return slist->isid;
}

int pt_image_validate(const struct pt_image *image, const struct pt_asid *asid,
		      uint64_t vaddr, const struct pt_section *section,
		      uint64_t laddr, int isid)
{
	struct pt_mapped_section *msec;
	struct pt_section_list *slist;

	if (!image)
		return -pte_internal;

	/* We only look at the top of our LRU stack and accept sporadic
	 * validation fails if @section moved down in the LRU stack or has been
	 * evicted.
	 *
	 * A failed validation requires decoders to re-fetch the section so it
	 * only results in a (relatively small) performance loss.
	 */
	slist = image->sections;
	if (!slist)
		return -pte_nomap;

	if (slist->isid != isid)
		return -pte_nomap;

	msec = &slist->section;

	if (pt_msec_section(msec) != section)
		return -pte_nomap;

	if (pt_msec_begin(msec) != laddr)
		return -pte_nomap;

	return pt_image_check_msec(msec, asid, vaddr);
}
