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

#include "memory.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(FEATURE_MMAP)
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <sys/user.h>
# include <fcntl.h>
# include <unistd.h>
#else
# include <stdlib.h>
# include <stdint.h>
#endif

/* Mapping information for mapped files. */
struct map_info {
	/* The pointer to the mapped memory we give out. */
	void *memory;

	/* The actual memory we mapped. */
	void *mmap;

	/* The size of the memory region we mapped. */
	size_t size;
};

enum {
	/* The number of entries in our map info cache. */
	mcache_max = 16
};

/* Our map info cache. */
static struct map_info mcache[mcache_max];


static struct map_info *lookup_mcache(void *mem)
{
	int i;

	for (i = 0; i < mcache_max; ++i) {
		if (mcache[i].memory == mem)
			return &mcache[i];
	}

	return NULL;
}

#if defined(FEATURE_MMAP)

void *map_file_section(const char *file, size_t offset, size_t size)
{
	struct map_info *cache;
	void *buffer;
	size_t adj;
	int fd;

	cache = lookup_mcache(NULL);
	if (!cache)
		return NULL;

	errno = 0;
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open: %s\n", file, strerror(errno));
		return NULL;
	}

	/* Mmap does not like unaligned offsets. */
	adj = offset % PAGE_SIZE;

	/* Adjust size and offset. */
	size += adj;
	offset -= adj;

	buffer = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (buffer == MAP_FAILED)
		fprintf(stderr, "%s: mmap failed: %s\n", file, strerror(errno));
	else {
		cache->memory = (char *)buffer + adj;
		cache->mmap = buffer;
		cache->size = size;
	}

	/* Mmap holds a reference to the file descriptor. */
	close(fd);
	return cache->memory;
}

void *map_file(const char *file, size_t *size)
{
	struct stat stat;
	void *buffer;
	int fd, errcode;

	buffer = NULL;
	errno = 0;
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open: %s\n", file, strerror(errno));
		return NULL;
	}

	errcode = fstat(fd, &stat);
	if (errcode < 0)
		fprintf(stderr, "%s: fstat failed: %s\n", file,
			strerror(errno));
	else {
		buffer = map_file_section(file, 0, stat.st_size);
		if (buffer && size)
			*size = stat.st_size;
	}

	close(fd);
	return buffer;
}

int unmap_memory(void *mem)
{
	struct map_info *cache;
	int errcode;

	cache = lookup_mcache(mem);
	if (!cache)
		return -EINVAL;

	errno = 0;
	errcode = munmap(cache->mmap, cache->size);
	if (errcode < 0)
		return -errno;

	cache->memory = NULL;
	cache->mmap = NULL;
	cache->size = 0;

	return 0;
}

#else /* defined(FEATURE_MMAP) */

void *map_file_section(const char *file, size_t offset, size_t size)
{
	struct map_info *cache;
	void *buffer;
	FILE *fd;
	int err;
	long foffset;

	cache = lookup_mcache(NULL);
	if (!cache)
		return NULL;

	errno = 0;
	fd = fopen(file, "rb");
	if (!fd) {
		fprintf(stderr, "%s: cannot open: %s\n", file, strerror(errno));
		return NULL;
	}

	foffset = (long) offset;
	err = fseek(fd, foffset, SEEK_SET);
	if (err) {
		fprintf(stderr, "%s: failed to seek %lx: %s\n", file, foffset,
			strerror(errno));
		fclose(fd);
		return NULL;
	}

	buffer = malloc(size);
	if (buffer) {
		uint8_t *pos, *end;

		pos = buffer;
		end = pos + size;

		while (pos < end) {
			int byte = fgetc(fd);

			if (byte == EOF)
				break;

			*pos++ = (uint8_t) byte;
		}

		cache->memory = buffer;
		cache->mmap = buffer;
		cache->size = pos - (uint8_t *) buffer;
	}

	fclose(fd);
	return buffer;
}

void *map_file(const char *file, size_t *size)
{
	FILE *fd;
	void *buffer;
	size_t fsize;
	int err;

	errno = 0;
	fd = fopen(file, "rb");
	if (!fd) {
		fprintf(stderr, "%s: cannot open: %s\n", file, strerror(errno));
		return NULL;
	}

	buffer = NULL;
	err = fseek(fd, 0, SEEK_END);
	if (err)
		fprintf(stderr, "%s: failed to seek end: %s\n", file,
			strerror(errno));
	else {
		fsize = ftell(fd);

		buffer = map_file_section(file, 0, fsize);
		if (buffer && size)
			*size = fsize;
	}

	fclose(fd);
	return buffer;
}

int unmap_memory(void *mem)
{
	struct map_info *cache;

	cache = lookup_mcache(mem);
	if (!cache)
		return -EINVAL;

	free(cache->mmap);

	cache->memory = NULL;
	cache->mmap = NULL;
	cache->size = 0;

	return 0;
}
#endif /* defined(FEATURE_MMAP) */
