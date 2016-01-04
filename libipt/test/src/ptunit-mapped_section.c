/*
 * Copyright (c) 2014-2016, Intel Corporation
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


/* A test mapping. */
struct sfix_mapping {
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

int pt_section_map(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

	if (section->mapping)
		return -pte_internal;

	section->mapping = section->status;
	return 0;
}

int pt_section_unmap(struct pt_section *section)
{
	if (!section)
		return -pte_internal;

	if (!section->mapping)
		return -pte_internal;

	section->mapping = NULL;
	return 0;
}

int pt_section_read(const struct pt_section *section, uint8_t *buffer,
		    uint16_t size, uint64_t offset)
{
	struct sfix_mapping *mapping;
	uint64_t begin, end;

	if (!section || !buffer)
		return -pte_invalid;

	mapping = section->mapping;
	if (!mapping)
		return -pte_nomap;

	if (mapping->size <= offset)
		return -pte_nomap;

	begin = offset;
	end = begin + size;

	if (mapping->size < end) {
		end = mapping->size;
		size = (uint16_t) (end - begin);
	}

	memcpy(buffer, &mapping->content[begin], size);

	return size;
}

/* A test fixture providing a test sections. */
struct section_fixture {
	/* The test mapping. */
	struct sfix_mapping mapping;

	/* The test section. */
	struct pt_section section;

	/* The test mapped section. */
	struct pt_mapped_section msec;

	/* The address space of @msec. */
	struct pt_asid asid;

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
	ptu_uint_eq(sfix->msec.asid.size, sfix->asid.size);
	ptu_uint_eq(sfix->msec.asid.cr3, sfix->asid.cr3);

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

	pt_msec_init(&msec, NULL, NULL, 0x1000);

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

static struct ptunit_result asid_null(void)
{
	const struct pt_asid *asid;

	asid = pt_msec_asid(NULL);
	ptu_null(asid);

	return ptu_passed();
}

static struct ptunit_result asid(void)
{
	struct pt_mapped_section msec;
	struct pt_asid asid;
	const struct pt_asid *pasid;

	pt_asid_init(&asid);
	asid.cr3 = 0xa00;

	pt_msec_init(&msec, NULL, &asid, 0ull);

	pasid = pt_msec_asid(&msec);
	ptu_uint_eq(pasid->size, asid.size);
	ptu_uint_eq(pasid->cr3, asid.cr3);

	return ptu_passed();
}

static struct ptunit_result read(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, &sfix->asid, sfix->vaddr);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], sfix->mapping.content[0]);
	ptu_uint_eq(buffer[1], sfix->mapping.content[1]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_default_asid(struct section_fixture *sfix)
{
	struct pt_asid asid;
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	pt_asid_init(&asid);

	status = pt_msec_read(&sfix->msec, buffer, 2, &asid, sfix->vaddr);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], sfix->mapping.content[0]);
	ptu_uint_eq(buffer[1], sfix->mapping.content[1]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_offset(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, &sfix->asid,
			      sfix->vaddr + 3);
	ptu_int_eq(status, 2);
	ptu_uint_eq(buffer[0], sfix->mapping.content[3]);
	ptu_uint_eq(buffer[1], sfix->mapping.content[4]);
	ptu_uint_eq(buffer[2], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_truncated(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc, 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, &sfix->asid,
			      sfix->vaddr + sfix->section.size - 1);
	ptu_int_eq(status, 1);
	ptu_uint_eq(buffer[0], sfix->mapping.content[sfix->mapping.size - 1]);
	ptu_uint_eq(buffer[1], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_nomem_vaddr(struct section_fixture *sfix)
{
	uint8_t buffer[] = { 0xcc };
	int status;

	status = pt_msec_read(&sfix->msec, buffer, 2, &sfix->asid,
			      sfix->vaddr + sfix->section.size);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result read_nomem_asid(struct section_fixture *sfix)
{
	struct pt_asid asid;
	uint8_t buffer[] = { 0xcc };
	int status;

	pt_asid_init(&asid);
	asid.cr3 = 0xcece00ull;

	status = pt_msec_read(&sfix->msec, buffer, 2, &asid, sfix->vaddr);
	ptu_int_eq(status, -pte_nomap);
	ptu_uint_eq(buffer[0], 0xcc);

	return ptu_passed();
}

static struct ptunit_result sfix_init(struct section_fixture *sfix)
{
	uint8_t i;

	sfix->section.size = sfix->mapping.size = sizeof(sfix->mapping.content);
	sfix->vaddr = 0x1000;

	for (i = 0; i < sfix->mapping.size; ++i)
		sfix->mapping.content[i] = i;

	sfix->section.status = &sfix->mapping;
	sfix->section.mapping = NULL;

	pt_asid_init(&sfix->asid);
	sfix->asid.cr3 = 0x4200ull;

	pt_msec_init(&sfix->msec, &sfix->section, &sfix->asid, sfix->vaddr);

	return ptu_passed();
}

static struct ptunit_result sfix_fini(struct section_fixture *sfix)
{
	pt_msec_fini(&sfix->msec);

	return ptu_passed();
}

int main(int argc, char **argv)
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

	ptu_run(suite, asid_null);
	ptu_run(suite, asid);

	ptu_run_f(suite, read, sfix);
	ptu_run_f(suite, read_default_asid, sfix);
	ptu_run_f(suite, read_offset, sfix);
	ptu_run_f(suite, read_truncated, sfix);
	ptu_run_f(suite, read_nomem_vaddr, sfix);
	ptu_run_f(suite, read_nomem_asid, sfix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
