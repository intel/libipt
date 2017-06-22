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

#include "ptunit_threads.h"
#include "ptunit_mkfile.h"

#include "pt_section.h"
#include "pt_block_cache.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <stdio.h>


struct pt_block_cache *pt_bcache_alloc(uint64_t nentries)
{
	struct pt_block_cache *bcache;

	if (!nentries || (UINT32_MAX < nentries))
		return NULL;

	/* The cache is not really used by tests.  It suffices to allocate only
	 * the cache struct with the single default entry.
	 *
	 * We still set the number of entries to the requested size.
	 */
	bcache = malloc(sizeof(*bcache));
	if (bcache)
		bcache->nentries = (uint32_t) nentries;

	return bcache;
}

void pt_bcache_free(struct pt_block_cache *bcache)
{
	free(bcache);
}

/* A test fixture providing a temporary file and an initially NULL section. */
struct section_fixture {
	/* Threading support. */
	struct ptunit_thrd_fixture thrd;

	/* A temporary file name. */
	char *name;

	/* That file opened for writing. */
	FILE *file;

	/* The section. */
	struct pt_section *section;

	/* A cloned section. */
	struct pt_section *clone;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct section_fixture *);
	struct ptunit_result (*fini)(struct section_fixture *);
};

enum {
#if defined(FEATURE_THREADS)

	num_threads	= 4,

#endif /* defined(FEATURE_THREADS) */

	num_work	= 0x4000
};

static struct ptunit_result sfix_write_aux(struct section_fixture *sfix,
					   const uint8_t *buffer, size_t size)
{
	size_t written;

	written = fwrite(buffer, 1, size, sfix->file);
	ptu_uint_eq(written, size);

	fflush(sfix->file);

	return ptu_passed();
}

#define sfix_write(sfix, buffer)				\
	ptu_check(sfix_write_aux, sfix, buffer, sizeof(buffer))

static struct ptunit_result create(struct section_fixture *sfix)
{
	const char *name;
	uint8_t bytes[] = { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc };
	uint64_t offset, size;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	name = pt_section_filename(sfix->section);
	ptu_str_eq(name, sfix->name);

	offset = pt_section_offset(sfix->section);
	ptu_uint_eq(offset, 0x1ull);

	size = pt_section_size(sfix->section);
	ptu_uint_eq(size, 0x3ull);

	return ptu_passed();
}

static struct ptunit_result create_bad_offset(struct section_fixture *sfix)
{
	sfix->section = pt_mk_section(sfix->name, 0x10ull, 0x0ull);
	ptu_null(sfix->section);

	return ptu_passed();
}

static struct ptunit_result create_truncated(struct section_fixture *sfix)
{
	const char *name;
	uint8_t bytes[] = { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc };
	uint64_t offset, size;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, UINT64_MAX);
	ptu_ptr(sfix->section);

	name = pt_section_filename(sfix->section);
	ptu_str_eq(name, sfix->name);

	offset = pt_section_offset(sfix->section);
	ptu_uint_eq(offset, 0x1ull);

	size = pt_section_size(sfix->section);
	ptu_uint_eq(size, sizeof(bytes) - 1);

	return ptu_passed();
}

static struct ptunit_result create_empty(struct section_fixture *sfix)
{
	sfix->section = pt_mk_section(sfix->name, 0x0ull, 0x10ull);
	ptu_null(sfix->section);

	return ptu_passed();
}

static struct ptunit_result clone_null(void)
{
	struct pt_section *section;
	int errcode;

	section = NULL;

	errcode = pt_section_clone(NULL, section, 0ull, 1ull);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_section_clone(&section, NULL, 0ull, 1ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result filename_null(void)
{
	const char *name;

	name = pt_section_filename(NULL);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result size_null(void)
{
	uint64_t size;

	size = pt_section_size(NULL);
	ptu_uint_eq(size, 0ull);

	return ptu_passed();
}

static struct ptunit_result offset_null(void)
{
	uint64_t offset;

	offset = pt_section_offset(NULL);
	ptu_uint_eq(offset, 0ull);

	return ptu_passed();
}

static struct ptunit_result get_null(void)
{
	int errcode;

	errcode = pt_section_get(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result put_null(void)
{
	int errcode;

	errcode = pt_section_put(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result map_null(void)
{
	int errcode;

	errcode = pt_section_map(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result unmap_null(void)
{
	int errcode;

	errcode = pt_section_unmap(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result cache_null(void)
{
	struct pt_block_cache *bcache;

	bcache = pt_section_bcache(NULL);
	ptu_null(bcache);

	return ptu_passed();
}

static struct ptunit_result get_overflow(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	sfix->section->ucount = UINT16_MAX;

	errcode = pt_section_get(sfix->section);
	ptu_int_eq(errcode, -pte_overflow);

	sfix->section->ucount = 1;

	return ptu_passed();
}

static struct ptunit_result map_change(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	sfix_write(sfix, bytes);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, -pte_bad_image);

	return ptu_passed();
}

static struct ptunit_result map_put(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_put(sfix->section);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result unmap_nomap(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, -pte_nomap);

	return ptu_passed();
}

static struct ptunit_result map_overflow(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	sfix->section->mcount = UINT16_MAX;

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, -pte_internal);

	sfix->section->mcount = 0;

	return ptu_passed();
}

static struct ptunit_result get_put(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	errcode = pt_section_get(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_get(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_put(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_put(sfix->section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result map_unmap(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result read(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x0ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[1]);
	ptu_uint_eq(buffer[1], bytes[2]);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_null(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, NULL, 1, 0x0ull);
	ptu_int_eq(status, -pte_internal);
	ptu_uint_eq(buffer[0], 0xcc);

	status = pt_section_read(NULL, buffer, 1, 0x0ull);
	ptu_int_eq(status, -pte_internal);
	ptu_uint_eq(buffer[0], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_offset(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x1ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[2]);
	ptu_uint_eq(buffer[1], bytes[3]);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x2ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[3]);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_from_truncated(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x2ull, 0x10ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x1ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[3]);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_nomem(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 1, 0x3ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_overflow(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 1,
				 0xffffffffffff0000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_overflow_32bit(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 1,
				 0xff00000000ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result read_nomap(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 1, 0x0ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_unmap_map(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x0ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[1]);
	ptu_uint_eq(buffer[1], bytes[2]);
	ptu_uint_eq(buffer[2], 0xcc);

	memset(buffer, 0xcc, sizeof(buffer));

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x0ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);
	ptu_uint_eq(buffer[1], 0xcc);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_section_map(sfix->section);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->section, buffer, 2, 0x0ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[1]);
	ptu_uint_eq(buffer[1], bytes[2]);
	ptu_uint_eq(buffer[2], 0xcc);

	status = pt_section_unmap(sfix->section);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result clone_bad_range(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0xcc };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x2ull);
	ptu_ptr(sfix->section);

	errcode = pt_section_clone(&sfix->clone, sfix->section, 0x0ull, 0x2ull);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_section_clone(&sfix->clone, sfix->section, 0x2ull, 0x2ull);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result clone_head(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0xcc };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x2ull);
	ptu_ptr(sfix->section);

	status = pt_section_clone(&sfix->clone, sfix->section, 0x1ull, 0x1ull);
	ptu_int_eq(status, 0);

	status = pt_section_map(sfix->clone);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->clone, buffer, 2, 0x0ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[1]);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_section_unmap(sfix->clone);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result clone_tail(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0xcc };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x2ull);
	ptu_ptr(sfix->section);

	status = pt_section_clone(&sfix->clone, sfix->section, 0x2ull, 0x1ull);
	ptu_int_eq(status, 0);

	status = pt_section_map(sfix->clone);
	ptu_int_eq(status, 0);

	status = pt_section_read(sfix->clone, buffer, 2, 0x0ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[2]);
	ptu_uint_eq(buffer[1], 0xcc);

	status = pt_section_unmap(sfix->clone);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static int worker(void *arg)
{
	struct section_fixture *sfix;
	int it, errcode;

	sfix = arg;
	if (!sfix)
		return -pte_internal;

	for (it = 0; it < num_work; ++it) {
		uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
		int read;

		errcode = pt_section_get(sfix->section);
		if (errcode < 0)
			return errcode;

		errcode = pt_section_map(sfix->section);
		if (errcode < 0)
			goto out_put;

		read = pt_section_read(sfix->section, buffer, 2, 0x0ull);
		if (read < 0)
			goto out_unmap;

		errcode = -pte_invalid;
		if ((read != 2) || (buffer[0] != 0x2) || (buffer[1] != 0x4))
			goto out_unmap;

		errcode = pt_section_unmap(sfix->section);
		if (errcode < 0)
			goto out_put;

		errcode = pt_section_put(sfix->section);
		if (errcode < 0)
			return errcode;
	}

	return 0;

out_unmap:
	(void) pt_section_unmap(sfix->section);

out_put:
	(void) pt_section_put(sfix->section);
	return errcode;
}

static struct ptunit_result stress(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

#if defined(FEATURE_THREADS)
	{
		int thrd;

		for (thrd = 0; thrd < num_threads; ++thrd)
			ptu_test(ptunit_thrd_create, &sfix->thrd, worker, sfix);
	}
#endif /* defined(FEATURE_THREADS) */

	errcode = worker(sfix);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result cache(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	struct pt_block_cache *bcache;
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	bcache = pt_section_bcache(sfix->section);
	ptu_ptr(bcache);
	ptu_uint_eq(bcache->nentries, sfix->section->size);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	return ptu_passed();
}

static struct ptunit_result cache_disabled(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	struct pt_block_cache *bcache;
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	pt_section_disable_bcache(sfix->section);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result cache_enable_disable(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	struct pt_block_cache *bcache;
	int errcode;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull);
	ptu_ptr(sfix->section);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	pt_section_disable_bcache(sfix->section);

	bcache = pt_section_bcache(sfix->section);
	ptu_ptr(bcache);
	ptu_uint_eq(bcache->nentries, sfix->section->size);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	errcode = pt_section_map(sfix->section);
	ptu_int_eq(errcode, 0);

	bcache = pt_section_bcache(sfix->section);
	ptu_null(bcache);

	errcode = pt_section_unmap(sfix->section);
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result sfix_init(struct section_fixture *sfix)
{
	int errcode;

	sfix->section = NULL;
	sfix->clone = NULL;
	sfix->file = NULL;
	sfix->name = NULL;

	errcode = ptunit_mkfile(&sfix->file, &sfix->name, "wb");
	ptu_int_eq(errcode, 0);

	ptu_test(ptunit_thrd_init, &sfix->thrd);

	return ptu_passed();
}

static struct ptunit_result sfix_fini(struct section_fixture *sfix)
{
	int thrd;

	ptu_test(ptunit_thrd_fini, &sfix->thrd);

	for (thrd = 0; thrd < sfix->thrd.nthreads; ++thrd)
		ptu_int_eq(sfix->thrd.result[thrd], 0);

	if (sfix->section) {
		pt_section_put(sfix->section);
		sfix->section = NULL;
	}

	if (sfix->clone) {
		pt_section_put(sfix->clone);
		sfix->clone = NULL;
	}

	if (sfix->file) {
		fclose(sfix->file);
		sfix->file = NULL;

		if (sfix->name)
			remove(sfix->name);
	}

	if (sfix->name) {
		free(sfix->name);
		sfix->name = NULL;
	}

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct section_fixture sfix;
	struct ptunit_suite suite;

	sfix.init = sfix_init;
	sfix.fini = sfix_fini;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run_f(suite, create, sfix);
	ptu_run_f(suite, create_bad_offset, sfix);
	ptu_run_f(suite, create_truncated, sfix);
	ptu_run_f(suite, create_empty, sfix);

	ptu_run(suite, clone_null);
	ptu_run(suite, filename_null);
	ptu_run(suite, offset_null);
	ptu_run(suite, size_null);
	ptu_run(suite, get_null);
	ptu_run(suite, put_null);
	ptu_run(suite, map_null);
	ptu_run(suite, unmap_null);
	ptu_run(suite, cache_null);

	ptu_run_f(suite, get_overflow, sfix);
	ptu_run_f(suite, map_change, sfix);
	ptu_run_f(suite, map_put, sfix);
	ptu_run_f(suite, unmap_nomap, sfix);
	ptu_run_f(suite, map_overflow, sfix);
	ptu_run_f(suite, get_put, sfix);
	ptu_run_f(suite, map_unmap, sfix);
	ptu_run_f(suite, read, sfix);
	ptu_run_f(suite, read_null, sfix);
	ptu_run_f(suite, read_offset, sfix);
	ptu_run_f(suite, read_truncated, sfix);
	ptu_run_f(suite, read_from_truncated, sfix);
	ptu_run_f(suite, read_nomem, sfix);
	ptu_run_f(suite, read_overflow, sfix);
	ptu_run_f(suite, read_overflow_32bit, sfix);
	ptu_run_f(suite, read_nomap, sfix);
	ptu_run_f(suite, read_unmap_map, sfix);
	ptu_run_f(suite, stress, sfix);

	ptu_run_f(suite, clone_bad_range, sfix);
	ptu_run_f(suite, clone_head, sfix);
	ptu_run_f(suite, clone_tail, sfix);

	ptu_run_f(suite, cache, sfix);
	ptu_run_f(suite, cache_disabled, sfix);
	ptu_run_f(suite, cache_enable_disable, sfix);

	return ptunit_report(&suite);
}
