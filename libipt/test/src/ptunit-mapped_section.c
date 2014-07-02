/*
 * Copyright (c) 2014, Intel Corporation
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

#include "pt_section.h"
#include "pt_mapped_section.h"

#include "intel-pt.h"


/* A test section. */
struct pt_section {
	/* The contents. */
	uint8_t content[0x10];

	/* The size - between 0 and sizeof(content). */
	uint64_t size;
};

uint64_t pt_section_size(const struct pt_section *section)
{
	if (!section)
		return 0ull;

	return section->size;
}

int pt_section_read(const struct pt_section *section, uint8_t *buffer,
		    uint16_t size, uint64_t offset)
{
	uint64_t begin, end;

	if (!section || !buffer)
		return -pte_invalid;

	if (section->size <= offset)
		return -pte_nomap;

	begin = offset;
	end = begin + size;

	if (section->size < end) {
		end = section->size;
		size = (uint16_t) (end - begin);
	}

	memcpy(buffer, &section->content[begin], size);

	return size;
}

/* A test fixture providing a test sections. */
struct section_fixture {
	/* The test section. */
	struct pt_section section;

	/* The test mapped section. */
	struct pt_mapped_section msec;

	/* The virtual address of @msec. */
	uint64_t vaddr;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct section_fixture *);
	struct ptunit_result (*fini)(struct section_fixture *);
};


static struct ptunit_result init(struct section_fixture *sfix)
{
	ptu_ptr_eq(sfix->msec.section, &sfix->section);
	ptu_uint_eq(sfix->msec.vaddr, sfix->vaddr);

	return ptu_passed();
}

static struct ptunit_result begin_null(void)
{
	uint64_t begin;

	begin = pt_msec_begin(NULL);
	ptu_uint_eq(begin, 0ull);

	return ptu_passed();
}

static struct ptunit_result end_null(void)
{
	uint64_t end;

	end = pt_msec_end(NULL);
	ptu_uint_eq(end, 0ull);

	return ptu_passed();
}

static struct ptunit_result end_bad(void)
{
	struct pt_mapped_section msec;
	uint64_t end;

	pt_msec_init(&msec, NULL, 0x1000);

	end = pt_msec_end(&msec);
	ptu_uint_eq(end, 0ull);

	return ptu_passed();
}

static struct ptunit_result begin(struct section_fixture *sfix)
{
	uint64_t begin;

	begin = pt_msec_begin(&sfix->msec);
	ptu_uint_eq(begin, sfix->vaddr);

	return ptu_passed();
}

static struct ptunit_result end(struct section_fixture *sfix)
{
	uint64_t end;

	end = pt_msec_end(&sfix->msec);
	ptu_uint_eq(end, sfix->vaddr + sfix->section.size);

	return ptu_passed();
}

static struct ptunit_result read(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, sfix->vaddr);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], sfix->section.content[0]);
	ptu_uint_eq(buffer[1], sfix->section.content[1]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_offset(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, sfix->vaddr + 3);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], sfix->section.content[3]);
	ptu_uint_eq(buffer[1], sfix->section.content[4]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2,
			      sfix->vaddr + sfix->section.size - 1);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], sfix->section.content[sfix->section.size - 1]);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_nomem(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2,
			      sfix->vaddr + sfix->section.size);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result sfix_init(struct section_fixture *sfix)
{
	uint8_t i;

	sfix->section.size = sizeof(sfix->section.content);
	sfix->vaddr = 0x1000;

	for (i = 0; i < sfix->section.size; ++i)
		sfix->section.content[i] = i;

	pt_msec_init(&sfix->msec, &sfix->section, sfix->vaddr);

	return ptu_passed();
}

static struct ptunit_result sfix_fini(struct section_fixture *sfix)
{
	pt_msec_fini(&sfix->msec);

	return ptu_passed();
}

int main(int argc, const char **argv)
{
	struct section_fixture sfix;
	struct ptunit_suite suite;

	sfix.init = sfix_init;
	sfix.fini = sfix_fini;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run_f(suite, init, sfix);

	ptu_run(suite, begin_null);
	ptu_run(suite, end_null);
	ptu_run(suite, end_bad);

	ptu_run_f(suite, begin, sfix);
	ptu_run_f(suite, end, sfix);

	ptu_run_f(suite, read, sfix);
	ptu_run_f(suite, read_offset, sfix);
	ptu_run_f(suite, read_truncated, sfix);
	ptu_run_f(suite, read_nomem, sfix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
