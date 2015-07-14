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

#include "pt_image.h"
#include "pt_section.h"
#include "pt_asid.h"

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
						  uint64_t vaddr)
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
	struct pt_section_list *list;

	if (!image)
		return;

	for (list = image->sections; list; ) {
		struct pt_section_list *trash;

		trash = list;
		list = list->next;

		pt_section_list_free(trash);
	}

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

int pt_image_add(struct pt_image *image, struct pt_section *section,
		 const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_section_list **list, *next;
	uint64_t begin, end;
	int errcode;

	if (!image || !section)
		return -pte_internal;

	begin = vaddr;
	end = begin + pt_section_size(section);

	/* Check for overlaps while we move to the end of the list. */
	for (list = &(image->sections); *list; list = &((*list)->next)) {
		const struct pt_mapped_section *msec;
		uint64_t lbegin, lend;

		msec = &(*list)->section;

		errcode = pt_msec_matches_asid(msec, asid);
		if (errcode < 0)
			return errcode;

		if (!errcode)
			continue;

		lbegin = pt_msec_begin(msec);
		lend = pt_msec_end(msec);

		if (end <= lbegin)
			continue;
		if (lend <= begin)
			continue;

		return -pte_bad_image;
	}

	next = pt_mk_section_list(section, asid, vaddr);
	if (!next)
		return -pte_nomap;

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
		struct pt_section_list *trash;
		int errcode;

		trash = *list;
		msec = &trash->section;

		errcode = pt_msec_matches_asid(msec, asid);
		if (errcode < 0)
			return errcode;

		if (!errcode)
			continue;

		if (msec->section == section && msec->vaddr == vaddr) {
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

	errcode = pt_image_add(image, section, &asid, vaddr);
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

	ignored = 0;
	for (list = src->sections; list; list = list->next) {
		int errcode;

		errcode = pt_image_add(image, list->section.section,
				       &list->section.asid,
				       list->section.vaddr);
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
		struct pt_section_list *trash;
		const char *tname;

		trash = *list;
		msec = &trash->section;

		errcode = pt_msec_matches_asid(msec, &asid);
		if (errcode < 0)
			return errcode;

		if (!errcode) {
			list = &trash->next;
			continue;
		}

		tname = pt_section_filename(msec->section);

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
		struct pt_section_list *trash;

		trash = *list;
		msec = &trash->section;

		errcode = pt_msec_matches_asid(msec, &asid);
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

static int pt_image_read_callback(struct pt_image *image, uint8_t *buffer,
				  uint16_t size, const struct pt_asid *asid,
				  uint64_t addr)
{
	read_memory_callback_t *callback;

	if (!image)
		return -pte_internal;

	callback = image->readmem.callback;
	if (!callback)
		return -pte_nomap;

	return callback(buffer, size, asid, addr, image->readmem.context);
}

static int pt_image_read_cold(struct pt_image *image,
			      struct pt_section_list **list,
			      uint8_t *buffer, uint16_t size,
			      const struct pt_asid *asid, uint64_t addr)
{
	struct pt_section_list **start;

	if (!image || !list)
		return -pte_internal;

	start = &image->sections;
	while (*list) {
		struct pt_mapped_section *msec;
		struct pt_section_list *elem;
		struct pt_section *sec;
		int mapped, errcode, status;

		elem = *list;
		msec = &elem->section;
		sec = msec->section;

		mapped = elem->mapped;
		if (!mapped) {
			errcode = pt_section_map(sec);
			if (errcode < 0)
				return errcode;
		}

		status = pt_msec_read_mapped(msec, buffer, size, asid, addr);
		if (status < 0) {
			if (!mapped) {
				errcode = pt_section_unmap(sec);
				if (errcode < 0)
					return errcode;
			}

			list = &elem->next;
			continue;
		}

		/* Move the section to the front if it isn't already. */
		if (list != start) {
			*list = elem->next;
			elem->next = *start;
			*start = elem;
		}

		/* Keep the section mapped if it isn't already - provided we
		 * do cache recently used sections.
		 */
		if (!mapped) {
			uint16_t cache, already;

			already = image->mapped;
			cache = image->cache;
			if (cache) {
				elem->mapped = 1;

				already += 1;
				image->mapped = already;

				if (cache < already) {
					errcode = pt_image_prune_cache(image);
					if (errcode < 0)
						return errcode;
				}
			} else {
				errcode = pt_section_unmap(sec);
				if (errcode < 0)
					return errcode;
			}
		}

		return status;
	}

	return pt_image_read_callback(image, buffer, size, asid, addr);
}

int pt_image_read(struct pt_image *image, uint8_t *buffer, uint16_t size,
		  const struct pt_asid *asid, uint64_t addr)
{
	struct pt_section_list **list, **start;

	if (!image || !asid)
		return -pte_internal;

	start = &image->sections;
	for (list = start; *list;) {
		struct pt_mapped_section *msec;
		struct pt_section_list *elem;
		int status;

		elem = *list;
		msec = &elem->section;

		if (!elem->mapped)
			break;

		status = pt_msec_read_mapped(msec, buffer, size, asid, addr);
		if (status < 0) {
			list = &elem->next;
			continue;
		}

		/* Move the section to the front if it isn't already. */
		if (list != start) {
			*list = elem->next;
			elem->next = *start;
			*start = elem;
		}

		return status;
	}

	return pt_image_read_cold(image, list, buffer, size, asid, addr);
}
