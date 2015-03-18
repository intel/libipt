/*
 * Copyright (c) 2014-2015, Intel Corporation
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

#include "pt_mapped_section.h"
#include "pt_section.h"
#include "pt_asid.h"

#include "intel-pt.h"


void pt_msec_init(struct pt_mapped_section *msec, struct pt_section *section,
		  const struct pt_asid *asid, uint64_t vaddr)
{
	if (!msec)
		return;

	msec->section = section;
	msec->vaddr = vaddr;

	if (asid)
		msec->asid = *asid;
	else
		pt_asid_init(&msec->asid);
}

void pt_msec_fini(struct pt_mapped_section *msec)
{
	if (!msec)
		return;

	msec->section = NULL;
	msec->vaddr = 0ull;
}

uint64_t pt_msec_begin(const struct pt_mapped_section *msec)
{
	if (!msec)
		return 0ull;

	return msec->vaddr;
}

uint64_t pt_msec_end(const struct pt_mapped_section *msec)
{
	uint64_t size;

	if (!msec)
		return 0ull;

	size = pt_section_size(msec->section);
	if (!size)
		return 0ull;

	return msec->vaddr + size;
}

const struct pt_asid *pt_msec_asid(const struct pt_mapped_section *msec)
{
	if (!msec)
		return NULL;

	return &msec->asid;
}

int pt_msec_matches_asid(const struct pt_mapped_section *msec,
			 const struct pt_asid *asid)
{
	if (!msec || !asid)
		return -pte_internal;

	return pt_asid_match(&msec->asid, asid);
}

int pt_msec_read(const struct pt_mapped_section *msec, uint8_t *buffer,
		 uint16_t size, const struct pt_asid *asid, uint64_t addr)
{
	struct pt_section *sec;
	int errcode, status;

	if (!msec)
		return -pte_internal;

	sec = msec->section;

	errcode = pt_section_map(sec);
	if (errcode < 0)
		return errcode;

	status = pt_msec_read_mapped(msec, buffer, size, asid, addr);

	errcode = pt_section_unmap(sec);
	if (errcode < 0)
		return errcode;

	return status;
}

int pt_msec_read_mapped(const struct pt_mapped_section *msec, uint8_t *buffer,
			uint16_t size, const struct pt_asid *asid,
			uint64_t addr)
{
	struct pt_section *sec;
	int errcode, status;

	if (!msec || !asid)
		return -pte_internal;

	errcode = pt_msec_matches_asid(msec, asid);
	if (errcode < 0)
		return errcode;

	if (!errcode)
		return -pte_nomap;

	if (addr < msec->vaddr)
		return -pte_nomap;

	addr -= msec->vaddr;

	sec = msec->section;

	status = pt_section_read(sec, buffer, size, addr);

	return status;
}
