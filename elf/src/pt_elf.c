/*
 * Copyright (c) 2017-2018, Intel Corporation
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

#include "pt_elf.h"

#include <gelf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "intel-pt.h"


/* A list of executable segments. */
struct pt_elf_segment {
	/* The next segment in the list. */
	struct pt_elf_segment *next;

	/* The virtual address. */
	uint64_t vaddr;

	/* The size in memory in bytes. */
	uint64_t size;

	/* The segment flags. */
	uint64_t flags;

	/* The offset into @filename. */
	uint64_t offset;

	/* The name of the file containing the data.
	 *
	 * The string is owned by the segment struct.
	 */
	char *filename;
};

/* The parts of an ELF file we're interested in. */
struct pt_elf {
	/* The libelf view. */
	Elf *libelf;

	/* The filename. */
	const char *filename;

	/* The file descriptor. */
	int fd;

	/* The executable segments. */
	struct pt_elf_segment *segments;

	/* The lowest virtual address of all segments. */
	uint64_t vaddr;
};

static int pt_elf_init(struct pt_elf *elf, const char *filename)
{
	Elf *libelf;
	int fd;

	if (!elf || !filename)
		return -pte_internal;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -pte_bad_file;

	(void) elf_version(EV_CURRENT);

	libelf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		close(fd);
		return -pte_bad_file;
	}

	memset(elf, 0, sizeof(*elf));
	elf->libelf = libelf;
	elf->filename = filename;
	elf->fd = fd;

	return 0;
}

static void pt_elf_fini(struct pt_elf *elf)
{
	struct pt_elf_segment *seg;

	if (!elf)
		return;

	seg = elf->segments;
	while (seg) {
		struct pt_elf_segment *trash;

		trash = seg;
		seg = seg->next;

		free(trash->filename);
		free(trash);
	}

	elf_end(elf->libelf);
	close(elf->fd);
}

static char *dupstr(const char *str)
{
	char *dup;
	size_t len;

	if (!str)
		str = "(null)";

	len = strnlen(str, PATH_MAX);
	if (PATH_MAX <= len)
		return NULL;

	dup = malloc(len + 1);
	if (!dup)
		return NULL;

	strncpy(dup, str, len);
	dup[len] = 0;

	return dup;
}

static int pt_elf_read_load_segment(struct pt_elf *elf, GElf_Phdr *phdr)
{
	struct pt_elf_segment *seg;

	if (!elf || !phdr)
		return -pte_internal;

	if (!phdr->p_memsz)
		return 0;

	seg = malloc(sizeof(*seg));
	if (!seg)
		return -pte_nomem;

	memset(seg, 0, sizeof(*seg));
	seg->next = elf->segments;
	seg->vaddr = phdr->p_vaddr;
	seg->size = phdr->p_memsz;
	seg->flags = phdr->p_flags;

	if (phdr->p_filesz) {
		char *filename;

		filename = dupstr(elf->filename);
		if (!filename) {
			free(seg);
			return -pte_nomem;
		}

		seg->filename = filename;
		seg->offset = phdr->p_offset;
		seg->size = phdr->p_filesz;
	}

	elf->segments = seg;

	if (seg->vaddr < elf->vaddr)
		elf->vaddr = seg->vaddr;

	return 0;
}

static int pt_elf_read_segments(struct pt_elf *elf)
{
	size_t nphdrs, pidx;
	Elf *libelf;
	int errcode;

	if (!elf)
		return -pte_internal;

	libelf = elf->libelf;
	if (!libelf)
		return -pte_internal;

	errcode = elf_getphdrnum(libelf, &nphdrs);
	if (errcode < 0)
		return -pte_bad_file;

	elf->vaddr = UINT64_MAX;
	for (pidx = 0; pidx < nphdrs; ++pidx) {
		GElf_Phdr buffer, *phdr;

		phdr = gelf_getphdr(libelf, pidx, &buffer);
		if (!phdr)
			return -pte_bad_file;

		switch (phdr->p_type) {
		case PT_LOAD:
			errcode = pt_elf_read_load_segment(elf, phdr);
			if (errcode < 0)
				return errcode;

			break;
		}
	}

	return 0;
}

static int pt_elf_read(struct pt_elf *elf)
{
	return pt_elf_read_segments(elf);
}

static int pt_elf_add_section(struct pt_image_section_cache *iscache,
			      struct pt_image *image, const char *name,
			      uint64_t offset, uint64_t size, uint64_t vaddr)
{
	if (!iscache)
		return pt_image_add_file(image, name, offset, size, NULL,
					 vaddr);
	else {
		int isid;

		isid = pt_iscache_add_file(iscache, name, offset, size, vaddr);
		if (isid < 0)
			return isid;

		return pt_image_add_cached(image, iscache, isid, NULL);
	}
}

static int pt_elf_add_segments(struct pt_image_section_cache *iscache,
			       struct pt_image *image, const struct pt_elf *elf,
			       uint64_t base, uint32_t flags)
{
	struct pt_elf_segment *seg;
	uint64_t offset;
	int nsecs, errcode;

	if (!elf)
		return -pte_internal;

	offset = base ? (base - elf->vaddr) : 0ull;
	nsecs = 0;
	for (seg = elf->segments; seg; seg = seg->next) {

		if (!seg->filename)
			continue;

		if (!(seg->flags & PF_X))
			continue;

		if (flags & pte_verbose) {
			printf("%s:", seg->filename);
			printf("  offset=%016" PRIx64, seg->offset);
			printf(", size=%016" PRIx64, seg->size);
			printf(", vaddr=%016" PRIx64, seg->vaddr);
			if (offset)
				printf(" (+%" PRIx64 ")", offset);
			printf("\n");
		}

		errcode = pt_elf_add_section(iscache, image, seg->filename,
					     seg->offset, seg->size,
					     seg->vaddr + offset);
		if (errcode < 0)
			return errcode;

		nsecs += 1;
	}

	return nsecs;
}

int pt_elf_load_segments(struct pt_image_section_cache *iscache,
			 struct pt_image *image, const char *filename,
			 uint64_t base, uint32_t flags)
{
	struct pt_elf elf;
	int status;

	status = pt_elf_init(&elf, filename);
	if (status < 0)
		return status;

	status = pt_elf_read(&elf);
	if (status >= 0)
		status = pt_elf_add_segments(iscache, image, &elf, base, flags);

	pt_elf_fini(&elf);
	return status;
}
