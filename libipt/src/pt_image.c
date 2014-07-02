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

#include "pt_image.h"
#include "pt_section.h"

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

	list = malloc(sizeof(*list));
	if (!list)
		return NULL;

	list->next = NULL;
	pt_msec_init(&list->section, section, asid, vaddr);

	return list;
}

static void pt_section_list_free(struct pt_section_list *list)
{
	if (!list)
		return;

	pt_section_free(list->section.section);
	pt_msec_fini(&list->section);
	free(list);
}

void pt_image_init(struct pt_image *image, const char *name)
{
	if (!image)
		return;

	memset(image, 0, sizeof(*image));

	image->name = dupstr(name);
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

const char *pt_image_name(const struct pt_image *image)
{
	if (!image)
		return NULL;

	return image->name;
}

static int pt_asid_matches(const struct pt_asid *lhs, const struct pt_asid *rhs)
{
	uint64_t lcr3, rcr3;

	if (lhs == rhs)
		return 1;

	if (!lhs || !rhs)
		return 1;

	lcr3 = lhs->cr3;
	rcr3 = rhs->cr3;

	if (lcr3 != rcr3 && lcr3 != pt_asid_no_cr3 && rcr3 != pt_asid_no_cr3)
		return 0;

	return 1;
}

int pt_image_add(struct pt_image *image, struct pt_section *section,
		 const struct pt_asid *asid, uint64_t vaddr)
{
	struct pt_section_list **list, *next;
	uint64_t begin, end;

	if (!image || !section)
		return -pte_invalid;

	begin = vaddr;
	end = begin + pt_section_size(section);

	/* Check for overlaps while we move to the end of the list. */
	for (list = &(image->sections); *list; list = &((*list)->next)) {
		const struct pt_mapped_section *msec;
		uint64_t lbegin, lend;

		msec = &(*list)->section;

		if (!pt_asid_matches(pt_msec_asid(msec), asid))
			continue;

		lbegin = pt_msec_begin(msec);
		lend = pt_msec_end(msec);

		if (end < lbegin)
			continue;
		if (lend <= begin)
			continue;

		return -pte_bad_context;
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
		return -pte_invalid;

	for (list = &image->sections; *list; list = &((*list)->next)) {
		const struct pt_mapped_section *msec;
		struct pt_section_list *trash;

		trash = *list;
		msec = &trash->section;

		if (!pt_asid_matches(pt_msec_asid(msec), asid))
			continue;

		if (msec->section == section && msec->vaddr == vaddr) {
			if (image->cache == msec)
				image->cache = NULL;

			*list = trash->next;
			pt_section_list_free(trash);

			return 0;
		}
	}

	return -pte_bad_context;
}

int pt_image_remove_by_name(struct pt_image *image, const char *name,
			    const struct pt_asid *asid)
{
	struct pt_section_list **list;
	int removed;

	if (!image || !name)
		return -pte_invalid;

	removed = 0;
	for (list = &image->sections; *list;) {
		const struct pt_mapped_section *msec;
		struct pt_section_list *trash;
		const char *tname;

		trash = *list;
		msec = &trash->section;

		if (!pt_asid_matches(pt_msec_asid(msec), asid)) {
			list = &trash->next;
			continue;
		}

		tname = pt_section_filename(msec->section);

		if (tname && (strcmp(tname, name) == 0)) {
			if (image->cache == msec)
				image->cache = NULL;

			*list = trash->next;
			pt_section_list_free(trash);

			removed += 1;
		} else
			list = &trash->next;
	}

	return removed;
}

int pt_image_replace_callback(struct pt_image *image,
			      read_memory_callback_t *callback, void *context)
{
	if (!image)
		return -pte_invalid;

	image->readmem.callback = callback;
	image->readmem.context = context;

	return 0;
}

static int pt_image_read_from(struct pt_image *image,
			      const struct pt_mapped_section *msec,
			      uint8_t *buffer, uint16_t size,
			      const struct pt_asid *asid, uint64_t addr)
{
	int status;

	if (!buffer || !image || !msec)
		return -pte_invalid;

	if (!pt_asid_matches(pt_msec_asid(msec), asid))
		return -pte_nomap;

	status = pt_msec_read(msec, buffer, size, addr);
	if (status >= 0)
		image->cache = msec;

	return status;
}

int pt_image_read(struct pt_image *image, uint8_t *buffer, uint16_t size,
		  const struct pt_asid *asid, uint64_t addr)
{
	struct pt_section_list *list;
	read_memory_callback_t *callback;
	int status;

	if (!buffer || !image)
		return -pte_invalid;

	status = pt_image_read_from(image, image->cache, buffer, size, asid,
				    addr);
	if (status >= 0)
		return status;

	for (list = image->sections; list; list = list->next) {
		struct pt_mapped_section *msec;

		msec = &list->section;
		status = pt_image_read_from(image, msec, buffer, size, asid,
					    addr);
		if (status >= 0)
			return status;
	}

	callback = image->readmem.callback;
	if (callback)
		return callback(buffer, size, asid, addr,
				image->readmem.context);

	return -pte_nomap;
}
