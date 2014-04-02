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

#ifndef __PT_IMAGE_H__
#define __PT_IMAGE_H__

#include "intel-pt.h"

#include <stdint.h>

struct pt_section;


/* A list of sections. */
struct pt_section_list {
	/* The next list element. */
	struct pt_section_list *next;

	/* The section. */
	struct pt_section *section;
};

/* A process image consisting of a collection of sections. */
struct pt_image {
	/* The optional image name. */
	char *name;

	/* The list of sections. */
	struct pt_section_list *sections;

	/* The last section that satisfied a read request. */
	struct pt_section *cache;

	/* An optional read memory callback. */
	struct {
		/* The callback function. */
		read_memory_callback_t *callback;

		/* The callback context. */
		void *context;
	} readmem;
};

/* Initialize an image with an optional @name. */
extern void pt_image_init(struct pt_image *image, const char *name);

/* Finalize an image.
 *
 * This removes and frees all sections and frees the name.
 */
extern void pt_image_fini(struct pt_image *image);

/* Return the name of @image.
 *
 * Returns NULL if no name was given at pt_image_init() or if @image is NULL.
 */
extern const char *pt_image_name(const struct pt_image *image);

/* Test an image for emptiness.
 *
 * Returns non-zero if @image is empty or NULL.
 * Returns zero otherwise.
 */
extern int pt_image_is_empty(const struct pt_image *image);

/* Add a section to an image.
 *
 * Add @section to @image if @section fits without overlap.
 *
 * Successfully added sections will be freed when they are removed.
 *
 * Returns zero on success.
 * Returns -pte_invalid if @section or @image are NULL.
 * Returns -pte_bad_context if @section overlaps with a section in @image.
 */
extern int pt_image_add(struct pt_image *image, struct pt_section *section);

/* Remove a section from an image.
 *
 * Removes and frees @section from @image.
 *
 * Returns zero on success.
 * Returns -pte_invalid if @section or @image are NULL.
 * Returns -pte_bad_context if @image does not contain @section.
 */
extern int pt_image_remove(struct pt_image *image, struct pt_section *section);

/* Remove zero or more sections from an image by section name.
 *
 * Removes and frees all sections from @image whose name equals @name.
 *
 * Returns the number of removed sections on success.
 * Returns -pte_invalid if @section or @name are NULL.
 */
extern int pt_image_remove_by_name(struct pt_image *image, const char *name);

/* Replace the read memory callback.
 *
 * Replaces the existing read memory callback in @image with @callback and
 * the existing read memory context with @context.
 *
 * Returns zero on success.
 * Returns -pte_invalid if @image is NULL.
 */
extern int pt_image_replace_callback(struct pt_image *image,
				     read_memory_callback_t *callback,
				     void *context);

/* Read memory from an image.
 *
 * Reads at most @size bytes from @image at @addr into @buffer.
 *
 * Returns the number of bytes read on success, a negative error code otherwise.
 * Returns -pte_invalid if @section or @buffer are NULL.
 * Returns -pte_nomap if the section does not contain @addr.
 */
extern int pt_image_read(struct pt_image *image, uint8_t *buffer,
			 uint16_t size, uint64_t addr);

#endif /* __PT_IMAGE_H__ */
