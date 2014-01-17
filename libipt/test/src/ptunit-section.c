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
#include "ptunit_mktempname.h"

#include "pt_section.h"

#include "intel-pt.h"

#include <stdlib.h>


/* A test fixture providing a temporary file and an initially NULL section. */
struct section_fixture {
	/* A temporary file name. */
	char *name;

	/* That file opened for writing. */
	FILE *file;

	/* The section. */
	struct pt_section *section;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct section_fixture *);
	struct ptunit_result (*fini)(struct section_fixture *);
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
	uint64_t begin, end;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull, 0x1000ull);
	ptu_ptr(sfix->section);

	name = pt_section_filename(sfix->section);
	ptu_str_eq(name, sfix->name);

	begin = pt_section_begin(sfix->section);
	ptu_uint_eq(begin, 0x1000ull);

	end = pt_section_end(sfix->section);
	ptu_uint_eq(end, 0x1003ull);

	return ptu_passed();
}

static struct ptunit_result create_bad_offset(struct section_fixture *sfix)
{
	sfix->section = pt_mk_section(sfix->name, 0x10ull, 0x0ull, 0x1000ull);
	ptu_null(sfix->section);

	return ptu_passed();
}

static struct ptunit_result create_truncated(struct section_fixture *sfix)
{
	const char *name;
	uint8_t bytes[] = { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc };
	uint64_t begin, end;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x0ull, UINT64_MAX, 0x101ull);
	ptu_ptr(sfix->section);

	name = pt_section_filename(sfix->section);
	ptu_str_eq(name, sfix->name);

	begin = pt_section_begin(sfix->section);
	ptu_uint_eq(begin, 0x101ull);

	end = pt_section_end(sfix->section);
	ptu_uint_eq(end, 0x106ull);

	return ptu_passed();
}

static struct ptunit_result create_empty(struct section_fixture *sfix)
{
	sfix->section = pt_mk_section(sfix->name, 0x0ull, 0x10ull, 0x1000ull);
	ptu_null(sfix->section);

	return ptu_passed();
}

static struct ptunit_result free_null(struct section_fixture *sfix)
{
	pt_section_free(NULL);

	return ptu_passed();
}

static struct ptunit_result filename_null(struct section_fixture *sfix)
{
	const char *name;

	name = pt_section_filename(NULL);
	ptu_null(name);

	return ptu_passed();
}

static struct ptunit_result begin_null(struct section_fixture *sfix)
{
	uint64_t begin;

	begin = pt_section_begin(NULL);
	ptu_uint_eq(begin, 0ull);

	return ptu_passed();
}

static struct ptunit_result end_null(struct section_fixture *sfix)
{
	uint64_t end;

	end = pt_section_end(NULL);
	ptu_uint_eq(end, 0ull);

	return ptu_passed();
}

static struct ptunit_result read(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull, 0x1000ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 2, 0x1000ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[1]);
	ptu_uint_eq(buffer[1], bytes[2]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_offset(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 };
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull, 0x1000ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 2, 0x1001ull);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], bytes[2]);
	ptu_uint_eq(buffer[1], bytes[3]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull, 0x1000ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 2, 0x1002ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[3]);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_from_truncated(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc, 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x2ull, 0x10ull, 0x1000ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 2, 0x1001ull);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], bytes[3]);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_nomem(struct section_fixture *sfix)
{
	uint8_t bytes[] = { 0xcc, 0x2, 0x4, 0x6 }, buffer[] = { 0xcc };
	int status;

	sfix_write(sfix, bytes);

	sfix->section = pt_mk_section(sfix->name, 0x1ull, 0x3ull, 0x1000ull);
	ptu_ptr(sfix->section);

	status = pt_section_read(sfix->section, buffer, 1, 0x1003ull);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result sfix_init(struct section_fixture *sfix)
{
	sfix->section = NULL;
	sfix->file = NULL;
	sfix->name = NULL;

	sfix->name = mktempname();
	ptu_ptr(sfix->name);

	sfix->file = fopen(sfix->name, "wb");
	ptu_ptr(sfix->file);

	return ptu_passed();
}

static struct ptunit_result sfix_fini(struct section_fixture *sfix)
{
	if (sfix->section) {
		pt_section_free(sfix->section);
		sfix->section = NULL;
	}

	if (sfix->file) {
		fclose(sfix->file);
		sfix->file = NULL;
	}

	if (sfix->name) {
		free(sfix->name);
		sfix->name = NULL;
	}

	return ptu_passed();
}

int main(int argc, const char **argv)
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
	ptu_run_f(suite, free_null, sfix);
	ptu_run_f(suite, filename_null, sfix);
	ptu_run_f(suite, begin_null, sfix);
	ptu_run_f(suite, end_null, sfix);
	ptu_run_f(suite, read, sfix);
	ptu_run_f(suite, read_offset, sfix);
	ptu_run_f(suite, read_truncated, sfix);
	ptu_run_f(suite, read_from_truncated, sfix);
	ptu_run_f(suite, read_nomem, sfix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
