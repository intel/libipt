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

static struct pt_section_list *pt_mk_section_list(struct pt_section *section)
{
	struct pt_section_list *list;

	list = malloc(sizeof(*list));
	if (!list)
		return NULL;

	list->next = NULL;
	list->section = section;

	return list;
}

static void pt_section_list_free(struct pt_section_list *list)
{
	if (!list)
		return;

	pt_section_free(list->section);
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

int pt_image_is_empty(const struct pt_image *image)
{
	return !image || !image->sections;
}

int pt_image_add(struct pt_image *image, struct pt_section *section)
{
	struct pt_section_list **list, *next;
	uint64_t begin, end;

	if (!image || !section)
		return -pte_invalid;

	begin = pt_section_begin(section);
	end = pt_section_end(section);

	/* Check for overlaps while we move to the end of the list. */
	for (list = &(image->sections); *list; list = &((*list)->next)) {
		uint64_t lbegin, lend;

		lbegin = pt_section_begin((*list)->section);
		lend = pt_section_end((*list)->section);

		if (end < lbegin)
			continue;
		if (lend <= begin)
			continue;

		return -pte_bad_context;
	}

	next = pt_mk_section_list(section);
	if (!next)
		return -pte_nomap;

	*list = next;
	return 0;
}

int pt_image_remove(struct pt_image *image, struct pt_section *section)
{
	struct pt_section_list **list;

	if (!image || !section)
		return -pte_invalid;

	for (list = &image->sections; *list; list = &((*list)->next)) {
		struct pt_section_list *trash;

		trash = *list;
		if (trash->section == section) {
			if (image->cache == section)
				image->cache = NULL;

			*list = trash->next;
			pt_section_list_free(trash);

			return 0;
		}
	}

	return -pte_bad_context;
}

int pt_image_remove_by_name(struct pt_image *image, const char *name)
{
	struct pt_section_list **list;
	int removed;

	if (!image || !name)
		return -pte_invalid;

	removed = 0;
	for (list = &image->sections; *list;) {
		struct pt_section_list *trash;
		struct pt_section *section;
		const char *tname;

		trash = *list;
		section = trash->section;
		tname = pt_section_filename(section);

		if (tname && (strcmp(tname, name) == 0)) {
			if (image->cache == section)
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
			      struct pt_section *section,
			      uint8_t *buffer, uint16_t size, uint64_t addr)
{
	int status;

	if (!buffer || !image || !section)
		return -pte_invalid;

	status = pt_section_read(section, buffer, size, addr);
	if (status >= 0)
		image->cache = section;

	return status;
}

int pt_image_read(struct pt_image *image, uint8_t *buffer, uint16_t size,
		  uint64_t addr)
{
	struct pt_section_list *list;
	read_memory_callback_t *callback;
	int status;

	if (!buffer || !image)
		return -pte_invalid;

	status = pt_image_read_from(image, image->cache, buffer, size, addr);
	if (status >= 0)
		return status;

	for (list = image->sections; list; list = list->next) {
		struct pt_section *section;

		section = list->section;
		status = pt_image_read_from(image, section, buffer, size, addr);
		if (status >= 0)
			return status;
	}

	callback = image->readmem.callback;
	if (callback)
		return callback(buffer, size, addr, image->readmem.context);

	return -pte_nomap;
}
