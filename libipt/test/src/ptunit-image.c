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

#include "ptunit.h"

#include "pt_image.h"
#include "pt_section.h"

#include "intel-pt.h"

#include <stdlib.h>


/* A test section. */
struct pt_section {
	/* The file name. */
	const char *name;

	/* The contents. */
	uint8_t content[0x10];

	/* The size - between 0 and sizeof(content). */
	uint64_t size;

	/* The virtual address. */
	uint64_t address;

	/* Delete indication:
	 * - zero, if initialized and not (yet) deleted
	 * - non-zero if deleted and not (re-)initialized
	 */
	int deleted;
};

static struct ptunit_result pt_init_section(struct pt_section *section,
					    const char *file, uint64_t addr)

{
	uint8_t i;

	ptu_ptr(section);

	section->name = file;
	section->size = sizeof(section->content);
	section->address = addr;
	section->deleted = 0;

	for (i = 0; i < sizeof(section->content); ++i)
		section->content[i] = i;

	return ptu_passed();
}

void pt_section_free(struct pt_section *section)
{
	if (!section)
		return;

	section->deleted = 1;
}

const char *pt_section_filename(const struct pt_section *section)
{
	if (!section)
		return NULL;

	return section->name;
}

uint64_t pt_section_begin(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->address;
}

uint64_t pt_section_end(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->address + section->size;
}

int pt_section_read(struct pt_section *section, uint8_t *buffer, uint16_t size,
		    uint64_t addr)
{
	uint64_t begin, end;

	if (!section || !buffer)
		return -pte_invalid;

	if (addr < section->address)
		return -pte_nomap;

	begin = addr - section->address;
	end = begin + size;

	if (section->size <= begin)
		return -pte_nomap;

	if (section->size < end) {
		end = section->size;
		size = (uint16_t) (end - begin);
	}

	memcpy(buffer, &section->content[begin], size);

	return size;
}

/* A test fixture providing an image and two test sections. */
struct image_fixture {
	/* The image. */
	struct pt_image image;

	/* The sections. */
	struct pt_section section[2];

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct image_fixture *);
	struct ptunit_result (*fini)(struct image_fixture *);
};

/* A test read memory callback. */
static int image_readmem_callback(uint8_t *buffer, size_t size,
				  uint64_t ip, void *context)
{
	const uint8_t *memory;
	size_t idx;

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
	ptu_null(image.cache);
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
	ptu_null(ifix->image.cache);
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
	struct pt_section section;
	struct pt_image image;

	pt_image_init(&image, NULL);
	pt_init_section(&section, NULL, 0ull);
	pt_image_add(&image, &section);

	pt_image_fini(&image);
	ptu_int_eq(section.deleted, 1);

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

static struct ptunit_result empty(struct image_fixture *ifix)
{
	int status;

	status = pt_image_is_empty(&ifix->image);
	ptu_int_ne(status, 0);

	return ptu_passed();
}

static struct ptunit_result not_empty(struct image_fixture *ifix)
{
	int status;

	status = pt_image_is_empty(&ifix->image);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result is_empty_null(struct image_fixture *ifix)
{
	int status;

	status = pt_image_is_empty(NULL);
	ptu_int_ne(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_empty(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x1000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result overlap(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	ifix->section[0].address = 0x1000;
	ifix->section[1].address = 0x1008;

	status = pt_image_add(&ifix->image, &ifix->section[0]);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1]);
	ptu_int_eq(status, -pte_bad_context);

	status = pt_image_read(&ifix->image, buffer, 1, 0x1009ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x09);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_replace_callback(&ifix->image,
					   image_readmem_callback, NULL);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, 0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_callback(struct image_fixture *ifix)
{
	uint8_t memory[] = { 0xdd, 0x01, 0x02, 0xdd };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_replace_callback(&ifix->image,
					   image_readmem_callback, memory);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, 0x3001ull);
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

	status = pt_image_replace_callback(&ifix->image,
					   image_readmem_callback, NULL);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x1010ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x100full);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0x0f);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_section(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, 0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove(&ifix->image, &ifix->section[0]);
	ptu_int_eq(status, 0);

	ptu_int_ne(ifix->section[0].deleted, 0);
	ptu_int_eq(ifix->section[1].deleted, 0);

	status = pt_image_is_empty(&ifix->image);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, 0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_by_name(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_read(&ifix->image, buffer, 2, 0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_name(&ifix->image, ifix->section[0].name);
	ptu_int_eq(status, 1);

	ptu_int_ne(ifix->section[0].deleted, 0);
	ptu_int_eq(ifix->section[1].deleted, 0);

	status = pt_image_is_empty(&ifix->image);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, 0x2003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_none_by_name(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_image_remove_by_name(&ifix->image, "bad-name");
	ptu_int_eq(status, 0);

	ptu_int_eq(ifix->section[0].deleted, 0);
	ptu_int_eq(ifix->section[1].deleted, 0);

	status = pt_image_is_empty(&ifix->image);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, 0x1003ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x03);
	ptu_uint_eq(buffer[1], 0x04);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, 2, 0x2001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result remove_all_by_name(struct image_fixture *ifix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	ifix->section[0].name = "same-name";
	ifix->section[1].name = "same-name";

	status = pt_image_add(&ifix->image, &ifix->section[0]);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1]);
	ptu_int_eq(status, 0);

	status = pt_image_read(&ifix->image, buffer, 2, 0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_remove_by_name(&ifix->image, "same-name");
	ptu_int_eq(status, 2);

	ptu_int_ne(ifix->section[0].deleted, 0);
	ptu_int_ne(ifix->section[1].deleted, 0);

	status = pt_image_is_empty(&ifix->image);
	ptu_int_ne(status, 0);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_image_read(&ifix->image, buffer, sizeof(buffer), 0x2003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0x01);
	ptu_uint_eq(buffer[1], 0x02);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

struct ptunit_result ifix_init(struct image_fixture *ifix)
{
	pt_image_init(&ifix->image, NULL);

	pt_init_section(&ifix->section[0], "file-0", 0x1000ull);
	pt_init_section(&ifix->section[1], "file-1", 0x2000ull);

	return ptu_passed();
}

struct ptunit_result rfix_init(struct image_fixture *ifix)
{
	int status;

	ptu_check(ifix_init, ifix);

	status = pt_image_add(&ifix->image, &ifix->section[0]);
	ptu_int_eq(status, 0);

	status = pt_image_add(&ifix->image, &ifix->section[1]);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

struct ptunit_result dfix_fini(struct image_fixture *ifix)
{
	pt_image_fini(&ifix->image);

	return ptu_passed();
}

int main(int argc, const char **argv)
{
	struct image_fixture dfix, ifix, rfix;
	struct ptunit_suite suite;

	/* Dfix provides image destruction. */
	dfix.init = NULL;
	dfix.fini = dfix_fini;

	/* Ifix provides an empty image. */
	ifix.init = ifix_init;
	ifix.fini = dfix_fini;

	/* Rfix provides an image with two sections added. */
	rfix.init = rfix_init;
	rfix.fini = dfix_fini;

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

	ptu_run_f(suite, empty, ifix);
	ptu_run_f(suite, not_empty, rfix);
	ptu_run_f(suite, is_empty_null, rfix);

	ptu_run_f(suite, read_empty, ifix);
	ptu_run_f(suite, overlap, ifix);

	ptu_run_f(suite, read, rfix);
	ptu_run_f(suite, read_callback, rfix);
	ptu_run_f(suite, read_nomem, rfix);
	ptu_run_f(suite, read_truncated, rfix);

	ptu_run_f(suite, remove_section, rfix);
	ptu_run_f(suite, remove_by_name, rfix);
	ptu_run_f(suite, remove_none_by_name, rfix);
	ptu_run_f(suite, remove_all_by_name, ifix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
