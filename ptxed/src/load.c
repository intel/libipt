/*
 * Copyright (c) 2013, Intel Corporation
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

#include "load.h"
#include "memory.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#if defined(FEATURE_ELF)
# include <elf.h>
#endif /* defined(FEATURE_ELF) */


static char *alloc_string(const char *str)
{
	char *copy = NULL;

	if (str) {
		size_t size = strlen(str) + 1;

		copy = malloc(size);
		if (copy)
			memcpy(copy, str, size);
	}

	return copy;
}

#if defined(FEATURE_ELF)

static uint64_t min_load_addr_64(Elf64_Phdr *phdr, size_t size)
{
	uint64_t addr = UINT64_MAX;

	while (size--) {
		Elf64_Phdr *pentry = &phdr[size];

		if (pentry->p_type != PT_LOAD)
			continue;

		if (pentry->p_vaddr < addr)
			addr = pentry->p_vaddr;
	}

	return addr;
}

static int load_elf64(const char *file, struct load_map **lmap, uint64_t addr)
{
	size_t sizeof_phdr;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint64_t base;
	int64_t load_offset;
	int pidx, errcode;

	ehdr = map_file_section(file, 0, sizeof(*ehdr));
	if (!ehdr)
		return -errno;

	sizeof_phdr = ehdr->e_phnum * sizeof(*phdr);
	if (!sizeof_phdr) {
		fprintf(stderr, "error: %s: no program header.\n", file);
		errcode = -ENODATA;
		goto out_ehdr;
	}

	phdr = map_file_section(file, ehdr->e_phoff, sizeof_phdr);
	if (!phdr) {
		fprintf(stderr, "error: %s: "
			"failed to map program header: %d\n", file, errno);
		errcode = -errno;
		goto out_ehdr;
	}

	/* Determine the load offset. */
	base = min_load_addr_64(phdr, ehdr->e_phnum);
	load_offset = addr - base;

	/* If we do not find a loadable segment, signal an error. */
	errcode = -ENODATA;

	for (pidx = 0; pidx < ehdr->e_phnum; ++pidx) {
		Elf64_Phdr *pentry = &phdr[pidx];

		switch (pentry->p_type) {
		default:
			/* Skip this entry. */
			continue;

		case PT_LOAD: {
			struct load_map *next;

			next = malloc(sizeof(*next));
			if (!next) {
				errcode = -ENOMEM;
				fprintf(stderr, "warning: %s: "
					"failed to allocate memory: %d\n",
					file, errcode);
				goto out_phdr;
			}

			(void) memset(next, 0, sizeof(*next));
			next->next = *lmap;
			next->size = pentry->p_filesz;
			next->address = pentry->p_vaddr + load_offset;

			next->memory = map_file_section(file, pentry->p_offset,
							pentry->p_filesz);
			if (!next->memory) {
				fprintf(stderr, "warning: %s: failed to map "
					"section at 0x%" PRIx64 ": %d\n",
					file, next->address, errno);
				errcode = -errno;
				free(next);
				break;
			}

			if (pentry->p_filesz < pentry->p_memsz)
				fprintf(stderr, "warning: %s:  truncating "
					"segment at 0x%" PRIx64 "\n",
					file, next->address);

			next->file = alloc_string(file);

			*lmap = next;
			errcode = 0;
		}
			break;
		}
	}

out_phdr:
	unmap_memory(phdr);

out_ehdr:
	unmap_memory(ehdr);

	if (errcode == -ENODATA)
		fprintf(stderr,
			"warning: %s: did not find any load sections.\n", file);

	return errcode;
}

int load_elf(const char *file, struct load_map **lmap, uint64_t addr)
{
	uint8_t *e_ident;
	int errcode, bytes;

	if (!file || !lmap)
		return -EINVAL;

	e_ident = map_file_section(file, 0, EI_NIDENT);
	if (!e_ident)
		return -errno;

	for (bytes = 0; bytes < SELFMAG; ++bytes) {
		if (e_ident[bytes] != ELFMAG[bytes]) {
			errcode = -EBADF;
			goto out;
		}
	}

	switch (e_ident[EI_CLASS]) {
	default:
		fprintf(stderr, "unsupported ELF class: %d\n",
			e_ident[EI_CLASS]);
		errcode = -EBADF;
		break;

	case ELFCLASS64: {
		errcode = load_elf64(file, lmap, addr);
		break;
	}
	}

out:
	unmap_memory(e_ident);
	return errcode;
}

#else /* defined(FEATURE_ELF) */

int load_elf(const char *file , struct load_map **lmap, uint64_t addr)
{
	return -EOPNOTSUPP;
}

#endif /* defined(FEATURE_ELF) */

int load_raw(const char *file, struct load_map **lmap, uint64_t addr)
{
	struct load_map *next;

	next = malloc(sizeof(*next));
	if (!next)
		return -ENOMEM;

	(void) memset(next, 0, sizeof(*next));
	next->next = *lmap;
	next->address = addr;

	next->memory = map_file(file, &next->size);
	if (!next->memory) {
		free(next);
		return -ENOMEM;
	}

	next->file = alloc_string(file);

	*lmap = next;

	return 0;
}

void unload(struct load_map *lmap)
{
	int errcode;

	while (lmap) {
		struct load_map *trash;

		trash = lmap;
		lmap = lmap->next;

		errcode = unmap_memory(trash->memory);
		if (errcode < 0)
			fprintf(stderr,
				"failed to unload segment at 0x%" PRIx64
				": %s\n", trash->address, strerror(-errcode));

		/* We will leak the mapped memory in case of errors. */

		free(trash->file);
		free(trash);
	}
}

static struct load_map *find_map(struct load_map *lmap, uint64_t addr)
{
	for (; lmap; lmap = lmap->next) {
		if ((lmap->address <= addr) &&
		    (addr < (lmap->address + lmap->size)))
			break;
	}

	return lmap;
}

uint8_t *translate(struct load_map *lmap, uint64_t addr, uint64_t *space)
{
	lmap = find_map(lmap, addr);
	if (!lmap)
		return NULL;

	if (space)
		*space = lmap->size - (addr - lmap->address);

	return lmap->memory + (addr - lmap->address);
}
