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

#include "ptunit.h"

#include "pt_image.h"
#include "pt_section.h"
#include "pt_mapped_section.h"

#include "intel-pt.h"


/* A test mapping. */
struct ifix_mapping {
	/* The contents. */
	uint8_t content[0x10];

	/* The size - between 0 and sizeof(content). */
	uint64_t size;
};

/* A test file status - turned into a section status. */
struct ifix_status {
	/* Delete indication:
	 * - zero if initialized and not (yet) deleted
	 * - non-zero if deleted and not (re-)initialized
	 */
	int deleted;

	/* Put with use-count of zero indication. */
	int bad_put;

	/* The test mapping to be used. */
	struct ifix_mapping *mapping;
};

static void pt_init_section(struct pt_section *section, char *filename,
			    struct ifix_status *status,
			    struct ifix_mapping *mapping)
{
	uint8_t i;

	memset(section, 0, sizeof(*section));

	section->filename = filename;
	section->status = status;
	section->size = mapping->size = sizeof(mapping->content);

	for (i = 0; i < mapping->size; ++i)
		mapping->content[i] = i;

	status->deleted = 0;
	status->bad_put = 0;
	status->mapping = mapping;
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

struct pt_section *pt_mk_section(const char *file, uint64_t offset,
				 uint64_t size)
{
	(void) file;
	(void) offset;
	(void) size;

	/* This function is not used by our tests. */
	return NULL;
}

int pt_section_get(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

	section->ucount += 1;
	return 0;
}

int pt_section_put(struct pt_section *section)
{
	struct ifix_status *status;
	uint16_t ucount;

	if (!section)
		return -pte_internal;

	status = section->status;
	if (!status)
		return -pte_internal;

	ucount = section->ucount;
	if (!ucount) {
		status->bad_put += 1;

		return -pte_internal;
	}

	ucount = --section->ucount;
	if (!ucount) {
		status->deleted += 1;

		if (status->deleted > 1)
			return -pte_internal;
	}

	return 0;
}

static int ifix_unmap(struct pt_section *section)
{
	uint16_t mcount;

	if (!section)
		return -pte_internal;

	mcount = section->mcount;
	if (!mcount)
		return -pte_internal;

	if (!section->mapping)
		return -pte_internal;

	mcount = --section->mcount;
	if (!mcount)
		section->mapping = NULL;

	return 0;
}

static int ifix_read(const struct pt_section *section, uint8_t *buffer,
		     uint16_t size, uint64_t offset)
{
	struct ifix_mapping *mapping;
	uint64_t begin, end;

	if (!section || !buffer)
		return -pte_invalid;

	begin = offset;
	end = begin + size;

	if (end < begin)
		return -pte_nomap;

	mapping = section->mapping;
	if (!mapping)
		return -pte_nomap;

	if (mapping->size <= begin)
		return -pte_nomap;

	if (mapping->size < end) {
		end = mapping->size;
		size = (uint16_t) (end - begin);
	}

	memcpy(buffer, &mapping->content[begin], size);

	return size;
}

int pt_section_map(struct pt_section *section)
{
	struct ifix_status *status;
	uint16_t mcount;

	if (!section)
		return -pte_internal;

	mcount = section->mcount++;
	if (mcount)
		return 0;

	if (section->mapping)
		return -pte_internal;

	status = section->status;
	if (!status)
		return -pte_internal;

	section->mapping = status->mapping;
	section->unmap = ifix_unmap;
	section->read = ifix_read;

	return 0;
}

int pt_section_unmap(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

	if (!section->unmap)
		return -pte_nomap;

	return section->unmap(section);
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

/* A test fixture providing an image, test sections, and asids. */
struct image_fixture {
	/* The image. */
	struct pt_image image;

	/* The test states. */
	struct ifix_status status[3];

	/* The test mappings. */
	struct ifix_mapping mapping[3];

	/* The sections. */
	struct pt_section section[3];

	/* The asids. */
	struct pt_asid asid[3];

	/* An initially empty image as destination for image copies. */
	struct pt_image copy;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct image_fixture *);
	struct ptunit_result (*fini)(struct image_fixture *);
};

/* A test read memory callback. */
static int image_readmem_callback(uint8_t *buffer, size_t size,
				  const struct pt_asid *asid,
				  uint64_t ip, void *context)
{
	const uint8_t *memory;
	size_t idx;

	(void) asid;

	if (!buffer)
		return -pte_invalid;

	/* We use a constant offset of 0x3000. */
	if (ip < 0x3000ull)
		return -pte_nomap;

	ip -= 0x3000ull;

	memory = (const uint8_t *) context;
	if (!memory)
		return -pte_internal;

	for (idx = 0; idx < size; ++idx)
		buffer[idx] = memory[ip + idx];

	return (int) idx;
}

static struct ptunit_result init(void)
{
	struct pt_image image;

	memset(&image, 0xcd, sizeof(image));

	pt_image_init(&image, NULL);
	ptu_null(image.name);
	ptu_null(image.sections);
	ptu_null((void *) (uintptr_t) image.readmem.callback);
	ptu_null(image.readmem.context);

	return ptu_passed();
}

static struct ptunit_result init_name(struct image_fixture *ifix)
{
	memset(&ifix->image, 0xcd, sizeof(ifix->image));

	pt_image_init(&ifix->image, "image-name");
	ptu_str_eq(ifix->image.name, "image-name");
	ptu_null(ifix->image.sections);
	ptu_null((void *) (uintptr_t) ifix->image.readmem.callback);
	ptu_null(ifix->image.readmem.context);

	return ptu_passed();
}

static struct ptunit_result init_null(void)
{
	pt_image_init(NULL, NULL);

	return ptu_passed();
}

static struct ptunit_result fini(void)
{
	struct ifix_mapping mapping;
	struct ifix_status status;
	struct pt_section section;
	struct pt_image image;
	struct pt_asid asid;
	int errcode;

	pt_asid_init(&asid);
	pt_init_section(&section, NULL, &status, &mapping);

	pt_image_init(&image, NULL);
	errcode = pt_image_add(&image, &section, &asid, 0x0ull);
	ptu_int_eq(errcode, 0);

	pt_image_fini(&image);
	ptu_int_eq(section.ucount, 0);
	ptu_int_eq(section.mcount, 0);
	ptu_int_eq(status.deleted, 1);
	ptu_int_eq(status.bad_put, 0);

	return ptu_passed();
}

static struct ptunit_result fini_empty(void)
{
	struct pt_image image;

	pt_image_init(&image, NULL);
	pt_image_fini(&image);

	return ptu_passed();
}

static struct ptunit_result fini_null(void)
{
	pt_image_fini(NULL);

	return ptu_passed();
}

static struct ptunit_result name(struct image_fixture *ifix)
{
	const char *name;

	pt_image_init(&ifix->image, "image-name");

	name = pt_image_name(&ifix->image);
	ptu_str_eq(name, "image-name");

	return ptu_passed();
}

static struct ptunit_result name_none(void)
{
	struct pt_image image;
	const char *name;

	pt_image_init(&image, NULL);

	name = pt_image_name(&image);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result name_null(void)
{
	const char *name;

	name = pt_image_name(NULL);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result read_empty(struct image_fixture *ifix)
{
	struct pt_asid asid;
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	pt_asid_init(&asid);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), &asid,
			       0x1000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result overlap(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_add(&ifix->image, &ifix->section[0], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, -pte_bad_image);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[0],
			       0x1009ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x09);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result adjacent(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_add(&ifix->image, &ifix->section[0], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1], &ifix->asid[0],
			      0x1000ull - ifix->section[1].size);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[2], &ifix->asid[0],
			      0x1000ull + ifix->section[0].size);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[0],
			       0x1000ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x00);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[0],
			       0xfffull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0],
		    ifix->mapping[1].content[ifix->mapping[1].size - 1]);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[0],
			       0x1000ull + ifix->section[0].size);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x00);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_add(&ifix->image, &ifix->section[0], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1], &ifix->asid[1],
			      0x1008ull);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[0],
			       0x1009ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x09);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 1, &ifix->asid[1],
			       0x1009ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_bad_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x2003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_null_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, NULL, 0x2003ull);
	ptu_int_eq(status, -pte_internal);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_callback(struct image_fixture *ifix)
{
	uint8_t memory[] = { 0xdd, 0x01, 0x02, 0xdd };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_set_callback(&ifix->image, image_readmem_callback,
				       memory);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x3001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_nomem(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[1], 0x1010ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x100full);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x0f);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_section(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove(&ifix->image, &ifix->section[0],
				 &ifix->asid[0], 0x1000ull);
	ptu_int_eq(status, 0);

	ptu_int_ne(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_bad_vaddr(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove(&ifix->image, &ifix->section[0],
				 &ifix->asid[0], 0x2000ull);
	ptu_int_eq(status, -pte_bad_image);

	ptu_int_eq(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2005ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x05);
	ptu_uint_eq(buffer[1], 0x06);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_bad_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove(&ifix->image, &ifix->section[0],
				 &ifix->asid[1], 0x1000ull);
	ptu_int_eq(status, -pte_bad_image);

	ptu_int_eq(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2005ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x05);
	ptu_uint_eq(buffer[1], 0x06);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_by_filename(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_filename(&ifix->image,
					     ifix->section[0].filename,
					     &ifix->asid[0]);
	ptu_int_eq(status, 1);

	ptu_int_ne(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result
remove_by_filename_bad_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_filename(&ifix->image,
					     ifix->section[0].filename,
					     &ifix->asid[1]);
	ptu_int_eq(status, 0);

	ptu_int_eq(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2005ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x05);
	ptu_uint_eq(buffer[1], 0x06);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_none_by_filename(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_remove_by_filename(&ifix->image, "bad-name",
					     &ifix->asid[0]);
	ptu_int_eq(status, 0);

	ptu_int_eq(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_all_by_filename(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	ifix->section[0].filename = "same-name";
	ifix->section[1].filename = "same-name";

	status = pt_image_add(&ifix->image, &ifix->section[0], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1], &ifix->asid[0],
			      0x2000ull);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_filename(&ifix->image, "same-name",
					     &ifix->asid[0]);
	ptu_int_eq(status, 2);

	ptu_int_ne(ifix->status[0].deleted, 0);
	ptu_int_ne(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x2003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_by_asid(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[0],
			       0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_asid(&ifix->image, &ifix->asid[0]);
	ptu_int_eq(status, 1);

	ptu_int_ne(ifix->status[0].deleted, 0);
	ptu_int_eq(ifix->status[1].deleted, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer),
			       &ifix->asid[0], 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result copy_empty(struct image_fixture *ifix)
{
	struct pt_asid asid;
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	pt_asid_init(&asid);

	status = pt_image_copy(&ifix->copy, &ifix->image);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->copy, buffer, sizeof(buffer), &asid,
			       0x1000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result copy(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_copy(&ifix->copy, &ifix->image);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->copy, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result copy_duplicate(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_add(&ifix->copy, &ifix->section[1], &ifix->asid[1],
			      0x2000ull);
	ptu_int_eq(status, 0);

	status = pt_image_copy(&ifix->copy, &ifix->image);
	ptu_int_eq(status, 1);

	status = pt_image_read(&ifix->copy, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result copy_self(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_copy(&ifix->image, &ifix->image);
	ptu_int_eq(status, 2);

	status = pt_image_read(&ifix->image, buffer, 2, &ifix->asid[1],
			       0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

struct ptunit_result ifix_init(struct image_fixture *ifix)
{
	pt_image_init(&ifix->image, NULL);
	pt_image_init(&ifix->copy, NULL);

	pt_init_section(&ifix->section[0], "file-0", &ifix->status[0],
			&ifix->mapping[0]);
	pt_init_section(&ifix->section[1], "file-1", &ifix->status[1],
			&ifix->mapping[1]);
	pt_init_section(&ifix->section[2], "file-2", &ifix->status[2],
			&ifix->mapping[2]);

	pt_asid_init(&ifix->asid[0]);
	ifix->asid[0].cr3 = 0xa000;

	pt_asid_init(&ifix->asid[1]);
	ifix->asid[1].cr3 = 0xb000;

	pt_asid_init(&ifix->asid[2]);
	ifix->asid[2].cr3 = 0xc000;

	return ptu_passed();
}

struct ptunit_result rfix_init(struct image_fixture *ifix)
{
	int status;

	ptu_check(ifix_init, ifix);

	status = pt_image_add(&ifix->image, &ifix->section[0], &ifix->asid[0],
			      0x1000ull);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1], &ifix->asid[1],
			      0x2000ull);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

struct ptunit_result dfix_fini(struct image_fixture *ifix)
{
	pt_image_fini(&ifix->image);

	return ptu_passed();
}

struct ptunit_result ifix_fini(struct image_fixture *ifix)
{
	int sec;

	ptu_check(dfix_fini, ifix);

	pt_image_fini(&ifix->copy);

	for (sec = 0; sec < 3; ++sec) {
		ptu_int_eq(ifix->section[sec].ucount, 0);
		ptu_int_eq(ifix->section[sec].mcount, 0);
	}

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct image_fixture dfix, ifix, rfix;
	struct ptunit_suite suite;

	/* Dfix provides image destruction. */
	dfix.init = NULL;
	dfix.fini = dfix_fini;

	/* Ifix provides an empty image. */
	ifix.init = ifix_init;
	ifix.fini = ifix_fini;

	/* Rfix provides an image with two sections added. */
	rfix.init = rfix_init;
	rfix.fini = ifix_fini;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run(suite, init);
	ptu_run_f(suite, init_name, dfix);
	ptu_run(suite, init_null);

	ptu_run(suite, fini);
	ptu_run(suite, fini_empty);
	ptu_run(suite, fini_null);

	ptu_run_f(suite, name, dfix);
	ptu_run(suite, name_none);
	ptu_run(suite, name_null);

	ptu_run_f(suite, read_empty, ifix);
	ptu_run_f(suite, overlap, ifix);
	ptu_run_f(suite, adjacent, ifix);

	ptu_run_f(suite, read, rfix);
	ptu_run_f(suite, read_asid, ifix);
	ptu_run_f(suite, read_bad_asid, rfix);
	ptu_run_f(suite, read_null_asid, rfix);
	ptu_run_f(suite, read_callback, rfix);
	ptu_run_f(suite, read_nomem, rfix);
	ptu_run_f(suite, read_truncated, rfix);

	ptu_run_f(suite, remove_section, rfix);
	ptu_run_f(suite, remove_bad_vaddr, rfix);
	ptu_run_f(suite, remove_bad_asid, rfix);
	ptu_run_f(suite, remove_by_filename, rfix);
	ptu_run_f(suite, remove_by_filename_bad_asid, rfix);
	ptu_run_f(suite, remove_none_by_filename, rfix);
	ptu_run_f(suite, remove_all_by_filename, ifix);
	ptu_run_f(suite, remove_by_asid, rfix);

	ptu_run_f(suite, copy_empty, ifix);
	ptu_run_f(suite, copy, rfix);
	ptu_run_f(suite, copy_duplicate, rfix);
	ptu_run_f(suite, copy_self, rfix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
