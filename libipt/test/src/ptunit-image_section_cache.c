/*
 * Copyright (c) 2016-2017, Intel Corporation
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

#include "ptunit_threads.h"

#include "intel-pt.h"

#include <stdlib.h>


struct pt_section {
	/* The filename.  We only support string literals for testing. */
	const char *filename;

	/* The file offset and size. */
	uint64_t offset;
	uint64_t size;

	/* The file content. */
	uint8_t content[0x10];

	/* The use count. */
	int ucount;

	/* The map count. */
	int mcount;

#if defined(FEATURE_THREADS)
	/* A lock protecting this section. */
	mtx_t lock;
#endif /* defined(FEATURE_THREADS) */
};

extern struct pt_section *pt_mk_section(const char *filename, uint64_t offset,
					uint64_t size);

extern int pt_section_get(struct pt_section *section);
extern int pt_section_put(struct pt_section *section);

extern int pt_section_map(struct pt_section *section);
extern int pt_section_unmap(struct pt_section *section);

extern const char *pt_section_filename(const struct pt_section *section);
extern uint64_t pt_section_offset(const struct pt_section *section);
extern uint64_t pt_section_size(const struct pt_section *section);

extern int pt_section_read(const struct pt_section *section, uint8_t *buffer,
			   uint16_t size, uint64_t offset);


struct pt_section *pt_mk_section(const char *filename, uint64_t offset,
				 uint64_t size)
{
	struct pt_section *section;

	section = malloc(sizeof(*section));
	if (section) {
		uint8_t idx;

		section->filename = filename;
		section->offset = offset;
		section->size = size;
		section->ucount = 1;
		section->mcount = 0;

		for (idx = 0; idx < sizeof(section->content); ++idx)
			section->content[idx] = idx;

#if defined(FEATURE_THREADS)
		{
			int errcode;

			errcode = mtx_init(&section->lock, mtx_plain);
			if (errcode != thrd_success) {
				free(section);
				section = NULL;
			}
		}
#endif /* defined(FEATURE_THREADS) */
	}

	return section;
}

static int pt_section_lock(struct pt_section *section)
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

static int pt_section_unlock(struct pt_section *section)
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

int pt_section_get(struct pt_section *section)
{
	int errcode, ucount;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	ucount = ++section->ucount;

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	if (!ucount)
		return -pte_internal;

	return 0;
}

int pt_section_put(struct pt_section *section)
{
	int errcode, ucount;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	ucount = --section->ucount;

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	if (!ucount) {
#if defined(FEATURE_THREADS)
		mtx_destroy(&section->lock);
#endif /* defined(FEATURE_THREADS) */
		free(section);
	}

	return 0;
}

int pt_section_map(struct pt_section *section)
{
	int errcode, mcount;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	mcount = ++section->mcount;

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	if (mcount <= 0)
		return -pte_internal;

	return 0;
}

int pt_section_unmap(struct pt_section *section)
{
	int errcode, mcount;

	if (!section)
		return -pte_internal;

	errcode = pt_section_lock(section);
	if (errcode < 0)
		return errcode;

	mcount = --section->mcount;

	errcode = pt_section_unlock(section);
	if (errcode < 0)
		return errcode;

	if (mcount < 0)
		return -pte_internal;

	return 0;
}

const char *pt_section_filename(const struct pt_section *section)
{
	if (!section)
		return NULL;

	return section->filename;
}

uint64_t pt_section_offset(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->offset;
}

uint64_t pt_section_size(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->size;
}

int pt_section_read(const struct pt_section *section, uint8_t *buffer,
		    uint16_t size, uint64_t offset)
{
	uint64_t begin, end, max;

	if (!section || !buffer)
		return -pte_internal;

	begin = offset;
	end = begin + size;
	max = sizeof(section->content);

	if (max <= begin)
		return -pte_nomap;

	if (max < end)
		end = max;

	if (end <= begin)
		return -pte_invalid;

	memcpy(buffer, &section->content[begin], (size_t) (end - begin));
	return (int) (end - begin);
}

enum {
	/* The number of test sections. */
	num_sections	= 8,

#if defined(FEATURE_THREADS)

	num_threads	= 8,

#endif /* defined(FEATURE_THREADS) */

	num_iterations	= 0x1000
};

struct iscache_fixture {
	/* Threading support. */
	struct ptunit_thrd_fixture thrd;

	/* The image section cache under test. */
	struct pt_image_section_cache iscache;

	/* A bunch of test sections. */
	struct pt_section *section[num_sections];

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct iscache_fixture *);
	struct ptunit_result (*fini)(struct iscache_fixture *);
};

static struct ptunit_result dfix_init(struct iscache_fixture *cfix)
{
	int idx;

	ptu_test(ptunit_thrd_init, &cfix->thrd);

	memset(cfix->section, 0, sizeof(cfix->section));

	for (idx = 0; idx < num_sections; ++idx) {
		struct pt_section *section;

		section = pt_mk_section("some-filename",
					idx % 3 == 0 ? 0x1000 : 0x2000,
					idx % 2 == 0 ? 0x1000 : 0x2000);
		ptu_ptr(section);

		cfix->section[idx] = section;
	}

	return ptu_passed();
}

static struct ptunit_result cfix_init(struct iscache_fixture *cfix)
{
	int errcode;

	ptu_test(dfix_init, cfix);

	errcode = pt_iscache_init(&cfix->iscache, NULL);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result cfix_fini(struct iscache_fixture *cfix)
{
	int idx, errcode;

	ptu_test(ptunit_thrd_fini, &cfix->thrd);

	for (idx = 0; idx < cfix->thrd.nthreads; ++idx)
		ptu_int_eq(cfix->thrd.result[idx], 0);

	pt_iscache_fini(&cfix->iscache);

	for (idx = 0; idx < num_sections; ++idx) {
		ptu_int_eq(cfix->section[idx]->ucount, 1);
		ptu_int_eq(cfix->section[idx]->mcount, 0);

		errcode = pt_section_put(cfix->section[idx]);
		ptu_int_eq(errcode, 0);
	}

	return ptu_passed();
}


static struct ptunit_result init_null(void)
{
	int errcode;

	errcode = pt_iscache_init(NULL, NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result fini_null(void)
{
	pt_iscache_fini(NULL);

	return ptu_passed();
}

static struct ptunit_result name_null(void)
{
	const char *name;

	name = pt_iscache_name(NULL);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result add_null(void)
{
	struct pt_image_section_cache iscache;
	struct pt_section section;
	int errcode;

	errcode = pt_iscache_add(NULL, &section, 0ull);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_iscache_add(&iscache, NULL, 0ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result find_null(void)
{
	int errcode;

	errcode = pt_iscache_find(NULL, "filename", 0ull, 0ull, 0ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result lookup_null(void)
{
	struct pt_image_section_cache iscache;
	struct pt_section *section;
	uint64_t laddr;
	int errcode;

	errcode = pt_iscache_lookup(NULL, &section, &laddr, 0);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_iscache_lookup(&iscache, NULL, &laddr, 0);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_iscache_lookup(&iscache, &section, NULL, 0);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result clear_null(void)
{
	int errcode;

	errcode = pt_iscache_clear(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result free_null(void)
{
	pt_iscache_free(NULL);

	return ptu_passed();
}

static struct ptunit_result add_file_null(void)
{
	struct pt_image_section_cache iscache;
	int errcode;

	errcode = pt_iscache_add_file(NULL, "filename", 0ull, 0ull, 0ull);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_iscache_add_file(&iscache, NULL, 0ull, 0ull, 0ull);
	ptu_int_eq(errcode, -pte_invalid);

	return ptu_passed();
}

static struct ptunit_result read_null(void)
{
	struct pt_image_section_cache iscache;
	uint8_t buffer;
	int errcode;

	errcode = pt_iscache_read(NULL, &buffer, sizeof(buffer), 1ull, 0ull);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_iscache_read(&iscache, NULL, sizeof(buffer), 1ull, 0ull);
	ptu_int_eq(errcode, -pte_invalid);

	errcode = pt_iscache_read(&iscache, &buffer, 0ull, 1, 0ull);
	ptu_int_eq(errcode, -pte_invalid);

	return ptu_passed();
}

static struct ptunit_result init_fini(struct iscache_fixture *cfix)
{
	(void) cfix;

	/* The actual init and fini calls are in cfix_init() and cfix_fini(). */
	return ptu_passed();
}

static struct ptunit_result name(struct iscache_fixture *cfix)
{
	const char *name;

	pt_iscache_init(&cfix->iscache, "iscache-name");

	name = pt_iscache_name(&cfix->iscache);
	ptu_str_eq(name, "iscache-name");

	return ptu_passed();
}

static struct ptunit_result name_none(struct iscache_fixture *cfix)
{
	const char *name;

	pt_iscache_init(&cfix->iscache, NULL);

	name = pt_iscache_name(&cfix->iscache);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result add(struct iscache_fixture *cfix)
{
	int isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid, 0);

	/* The cache gets a reference on success. */
	ptu_int_eq(cfix->section[0]->ucount, 2);

	/* The added section must be implicitly put in pt_iscache_fini. */
	return ptu_passed();
}

static struct ptunit_result add_no_name(struct iscache_fixture *cfix)
{
	struct pt_section section;
	int errcode;

	memset(&section, 0, sizeof(section));

	errcode = pt_iscache_add(&cfix->iscache, &section, 0ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result add_file(struct iscache_fixture *cfix)
{
	int isid;

	isid = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 0ull);
	ptu_int_gt(isid, 0);

	return ptu_passed();
}

static struct ptunit_result find(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	found = pt_iscache_find(&cfix->iscache, section->filename,
				section->offset, section->size, 0ull);
	ptu_int_eq(found, isid);

	return ptu_passed();
}

static struct ptunit_result find_empty(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found;

	section = cfix->section[0];
	ptu_ptr(section);

	found = pt_iscache_find(&cfix->iscache, section->filename,
				section->offset, section->size, 0ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result find_bad_filename(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	found = pt_iscache_find(&cfix->iscache, "bad-filename",
				section->offset, section->size, 0ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result find_null_filename(struct iscache_fixture *cfix)
{
	int errcode;

	errcode = pt_iscache_find(&cfix->iscache, NULL, 0ull, 0ull, 0ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result find_bad_offset(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	found = pt_iscache_find(&cfix->iscache, section->filename, 0ull,
				section->size, 0ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result find_bad_size(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	found = pt_iscache_find(&cfix->iscache, section->filename,
				section->offset, 0ull, 0ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result find_bad_laddr(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	found = pt_iscache_find(&cfix->iscache, section->filename,
				section->offset, section->size, 1ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result lookup(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	uint64_t laddr;
	int errcode, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid, 0);

	errcode = pt_iscache_lookup(&cfix->iscache, &section, &laddr, isid);
	ptu_int_eq(errcode, 0);
	ptu_ptr_eq(section, cfix->section[0]);
	ptu_uint_eq(laddr, 0ull);

	errcode = pt_section_put(section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result lookup_bad_isid(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	uint64_t laddr;
	int errcode, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid, 0);

	errcode = pt_iscache_lookup(&cfix->iscache, &section, &laddr, 0);
	ptu_int_eq(errcode, -pte_bad_image);

	errcode = pt_iscache_lookup(&cfix->iscache, &section, &laddr, -isid);
	ptu_int_eq(errcode, -pte_bad_image);

	errcode = pt_iscache_lookup(&cfix->iscache, &section, &laddr, isid + 1);
	ptu_int_eq(errcode, -pte_bad_image);

	return ptu_passed();
}

static struct ptunit_result clear_empty(struct iscache_fixture *cfix)
{
	int errcode;

	errcode = pt_iscache_clear(&cfix->iscache);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result clear_find(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	int errcode, found, isid;

	section = cfix->section[0];
	ptu_ptr(section);

	isid = pt_iscache_add(&cfix->iscache, section, 0ull);
	ptu_int_gt(isid, 0);

	errcode = pt_iscache_clear(&cfix->iscache);
	ptu_int_eq(errcode, 0);


	found = pt_iscache_find(&cfix->iscache, section->filename,
				section->offset, section->size, 0ull);
	ptu_int_eq(found, 0);

	return ptu_passed();
}

static struct ptunit_result clear_lookup(struct iscache_fixture *cfix)
{
	struct pt_section *section;
	uint64_t laddr;
	int errcode, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid, 0);

	errcode = pt_iscache_clear(&cfix->iscache);
	ptu_int_eq(errcode, 0);

	errcode = pt_iscache_lookup(&cfix->iscache, &section, &laddr, isid);
	ptu_int_eq(errcode, -pte_bad_image);

	return ptu_passed();
}

static struct ptunit_result add_twice(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[1], 0);

	/* The second add should be ignored. */
	ptu_int_eq(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result add_same(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[0], 0);

	cfix->section[1]->offset = cfix->section[0]->offset;
	cfix->section[1]->size = cfix->section[0]->size;

	isid[1] = pt_iscache_add(&cfix->iscache, cfix->section[1], 0ull);
	ptu_int_gt(isid[1], 0);

	/* The second add should be ignored. */
	ptu_int_eq(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result
add_twice_different_laddr(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add(&cfix->iscache, cfix->section[0], 1ull);
	ptu_int_gt(isid[1], 0);

	/* We must get different identifiers. */
	ptu_int_ne(isid[1], isid[0]);

	/* We must take two references - one for each entry. */
	ptu_int_eq(cfix->section[0]->ucount, 3);

	return ptu_passed();
}

static struct ptunit_result
add_same_different_laddr(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[0], 0);

	cfix->section[1]->offset = cfix->section[0]->offset;
	cfix->section[1]->size = cfix->section[0]->size;

	isid[1] = pt_iscache_add(&cfix->iscache, cfix->section[1], 1ull);
	ptu_int_gt(isid[1], 0);

	/* We must get different identifiers. */
	ptu_int_ne(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result
add_different_same_laddr(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add(&cfix->iscache, cfix->section[0], 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add(&cfix->iscache, cfix->section[1], 0ull);
	ptu_int_gt(isid[1], 0);

	/* We must get different identifiers. */
	ptu_int_ne(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result add_file_same(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 0ull);
	ptu_int_gt(isid[1], 0);

	/* The second add should be ignored. */
	ptu_int_eq(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result
add_file_same_different_laddr(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 1ull);
	ptu_int_gt(isid[1], 0);

	/* We must get different identifiers. */
	ptu_int_ne(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result
add_file_different_same_laddr(struct iscache_fixture *cfix)
{
	int isid[2];

	isid[0] = pt_iscache_add_file(&cfix->iscache, "name", 0ull, 1ull, 0ull);
	ptu_int_gt(isid[0], 0);

	isid[1] = pt_iscache_add_file(&cfix->iscache, "name", 1ull, 1ull, 0ull);
	ptu_int_gt(isid[1], 0);

	/* We must get different identifiers. */
	ptu_int_ne(isid[1], isid[0]);

	return ptu_passed();
}

static struct ptunit_result read(struct iscache_fixture *cfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0xa000ull);
	ptu_int_gt(isid, 0);

	status = pt_iscache_read(&cfix->iscache, buffer, 2ull, isid, 0xa008ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], 0x8);
	ptu_uint_eq(buffer[1], 0x9);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncate(struct iscache_fixture *cfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0xa000ull);
	ptu_int_gt(isid, 0);

	status = pt_iscache_read(&cfix->iscache, buffer, sizeof(buffer), isid,
				 0xa00full);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], 0xf);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_bad_vaddr(struct iscache_fixture *cfix)
{
	uint8_t buffer[] = { 0xcc };
	int status, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0xa000ull);
	ptu_int_gt(isid, 0);

	status = pt_iscache_read(&cfix->iscache, buffer, 1ull, isid, 0xb000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_bad_isid(struct iscache_fixture *cfix)
{
	uint8_t buffer[] = { 0xcc };
	int status, isid;

	isid = pt_iscache_add(&cfix->iscache, cfix->section[0], 0xa000ull);
	ptu_int_gt(isid, 0);

	status = pt_iscache_read(&cfix->iscache, buffer, 1ull, isid + 1,
				 0xa000ull);
	ptu_int_eq(status, -pte_bad_image);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static int worker_add(void *arg)
{
	struct iscache_fixture *cfix;
	int it;

	cfix = arg;
	if (!cfix)
		return -pte_internal;

	for (it = 0; it < num_iterations; ++it) {
		uint64_t laddr;
		int sec;

		laddr = 0x1000ull * (it % 23);

		for (sec = 0; sec < num_sections; ++sec) {
			struct pt_section *section;
			uint64_t addr;
			int isid, errcode;

			isid = pt_iscache_add(&cfix->iscache,
					      cfix->section[sec], laddr);
			if (isid < 0)
				return isid;

			errcode = pt_iscache_lookup(&cfix->iscache, &section,
						    &addr, isid);
			if (errcode < 0)
				return errcode;

			if (laddr != addr)
				return -pte_noip;

			/* We may not get the image we added but the image we
			 * get must have similar attributes.
			 *
			 * We're using the same filename string literal for all
			 * sections, though.
			 */
			if (section->offset != cfix->section[sec]->offset)
				return -pte_bad_image;

			if (section->size != cfix->section[sec]->size)
				return -pte_bad_image;

			errcode = pt_section_put(section);
			if (errcode < 0)
				return errcode;
		}
	}

	return 0;
}

static int worker_add_file(void *arg)
{
	struct iscache_fixture *cfix;
	int it;

	cfix = arg;
	if (!cfix)
		return -pte_internal;

	for (it = 0; it < num_iterations; ++it) {
		uint64_t offset, size, laddr;
		int sec;

		offset = it % 7 == 0 ? 0x1000 : 0x2000;
		size = it % 5 == 0 ? 0x1000 : 0x2000;
		laddr = it % 3 == 0 ? 0x1000 : 0x2000;

		for (sec = 0; sec < num_sections; ++sec) {
			struct pt_section *section;
			uint64_t addr;
			int isid, errcode;

			isid = pt_iscache_add_file(&cfix->iscache, "name",
						   offset, size, laddr);
			if (isid < 0)
				return isid;

			errcode = pt_iscache_lookup(&cfix->iscache, &section,
						    &addr, isid);
			if (errcode < 0)
				return errcode;

			if (laddr != addr)
				return -pte_noip;

			if (section->offset != offset)
				return -pte_bad_image;

			if (section->size != size)
				return -pte_bad_image;

			errcode = pt_section_put(section);
			if (errcode < 0)
				return errcode;
		}
	}

	return 0;
}

static struct ptunit_result stress(struct iscache_fixture *cfix,
				   int (*worker)(void *))
{
	int errcode;

#if defined(FEATURE_THREADS)
	{
		int thrd;

		for (thrd = 0; thrd < num_threads; ++thrd)
			ptu_test(ptunit_thrd_create, &cfix->thrd, worker, cfix);
	}
#endif /* defined(FEATURE_THREADS) */

	errcode = worker(cfix);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}
int main(int argc, char **argv)
{
	struct iscache_fixture cfix, dfix;
	struct ptunit_suite suite;

	cfix.init = cfix_init;
	cfix.fini = cfix_fini;

	dfix.init = dfix_init;
	dfix.fini = cfix_fini;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run(suite, init_null);
	ptu_run(suite, fini_null);
	ptu_run(suite, name_null);
	ptu_run(suite, add_null);
	ptu_run(suite, find_null);
	ptu_run(suite, lookup_null);
	ptu_run(suite, clear_null);
	ptu_run(suite, free_null);
	ptu_run(suite, add_file_null);
	ptu_run(suite, read_null);

	ptu_run_f(suite, name, dfix);
	ptu_run_f(suite, name_none, dfix);

	ptu_run_f(suite, init_fini, cfix);
	ptu_run_f(suite, add, cfix);
	ptu_run_f(suite, add_no_name, cfix);
	ptu_run_f(suite, add_file, cfix);

	ptu_run_f(suite, find, cfix);
	ptu_run_f(suite, find_empty, cfix);
	ptu_run_f(suite, find_bad_filename, cfix);
	ptu_run_f(suite, find_null_filename, cfix);
	ptu_run_f(suite, find_bad_offset, cfix);
	ptu_run_f(suite, find_bad_size, cfix);
	ptu_run_f(suite, find_bad_laddr, cfix);

	ptu_run_f(suite, lookup, cfix);
	ptu_run_f(suite, lookup_bad_isid, cfix);

	ptu_run_f(suite, clear_empty, cfix);
	ptu_run_f(suite, clear_find, cfix);
	ptu_run_f(suite, clear_lookup, cfix);

	ptu_run_f(suite, add_twice, cfix);
	ptu_run_f(suite, add_same, cfix);
	ptu_run_f(suite, add_twice_different_laddr, cfix);
	ptu_run_f(suite, add_same_different_laddr, cfix);
	ptu_run_f(suite, add_different_same_laddr, cfix);

	ptu_run_f(suite, add_file_same, cfix);
	ptu_run_f(suite, add_file_same_different_laddr, cfix);
	ptu_run_f(suite, add_file_different_same_laddr, cfix);

	ptu_run_f(suite, read, cfix);
	ptu_run_f(suite, read_truncate, cfix);
	ptu_run_f(suite, read_bad_vaddr, cfix);
	ptu_run_f(suite, read_bad_isid, cfix);

	ptu_run_fp(suite, stress, cfix, worker_add);
	ptu_run_fp(suite, stress, cfix, worker_add_file);

	return ptunit_report(&suite);
}
