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

#if defined(FEATURE_PEVENT)
#  include <linux/perf_event.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

#include "intel-pt.h"


#ifndef NT_FILE
#  define NT_FILE	0x46494c45
#endif


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

/* A list of files from CORE/NT_FILE notes. */
struct pt_elf_file {
	/* The next file in the list. */
	struct pt_elf_file *next;

	/* The virtual address. */
	uint64_t vaddr;

	/* The size in memory in bytes. */
	uint64_t size;

	/* The offset into @filename. */
	uint64_t offset;

	/* The name of the file. */
	const char *filename;
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

	/* The files in core notes. */
	struct pt_elf_file *files;
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
	struct pt_elf_file *file;

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

	file = elf->files;
	while (file) {
		struct pt_elf_file *trash;

		trash = file;
		file = file->next;

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

	/* For executable segments, if the coredump does not contain the entire
	 * file (e.g. just the ELF header), we take the rest from the original
	 * file referenced in file notes.
	 *
	 * Setup an additional segment for the remainder without a filename.
	 */
	if ((phdr->p_flags & PF_X) && phdr->p_filesz < phdr->p_memsz) {
		seg = malloc(sizeof(*seg));
		if (!seg)
			return -pte_nomem;

		memset(seg, 0, sizeof(*seg));
		seg->next = elf->segments;
		seg->vaddr = phdr->p_vaddr + phdr->p_filesz;
		seg->size = phdr->p_memsz - phdr->p_filesz;
		seg->flags = phdr->p_flags;

		elf->segments = seg;
	}

	return 0;
}

static int pt_elf_next_filename(const char **next, const char **ftable,
				const char *end)
{
	const char *it;

	if (!next || !ftable || !end)
		return -pte_internal;

	*next = it = *ftable;
	while (it < end) {
		if (*it++)
			continue;

		*ftable = it;
		return 0;
	}

	return -pte_bad_file;
}

static int pt_elf_add_file(struct pt_elf *elf, uint64_t vaddr, uint64_t size,
			   uint64_t offset, const char **ftable,
			   const char *end)
{
	struct pt_elf_file *file;
	const char *fname;
	int errcode;

	if (!elf)
		return -pte_internal;

	errcode = pt_elf_next_filename(&fname, ftable, end);
	if (errcode < 0)
		return errcode;

	file = malloc(sizeof(*file));
	if (!file)
		return -pte_nomem;

	memset(file, 0, sizeof(*file));
	file->next = elf->files;
	file->vaddr = vaddr;
	file->size = size;
	file->offset = offset;
	file->filename = fname;

	elf->files = file;

	return 0;
}

static int pt_elf_read_file_note_64(struct pt_elf *elf, const uint64_t *desc,
				    size_t size)
{
	const char *ftable, *bound;
	uint64_t nentries, pgsz, idx;

	if (!elf || !desc)
		return -pte_internal;

	bound = (const char *) desc + size;

	nentries = *desc++;
	pgsz = *desc++;

	ftable = (const char *) desc + (sizeof(*desc) * 3 * nentries);
	if (bound < ftable)
		return -pte_bad_file;

	for (idx = 0; idx < nentries; ++idx) {
		uint64_t begin, end, offset;
		int errcode;

		begin = *desc++;
		end = *desc++;
		offset = *desc++;

		if (end < begin)
			return -pte_bad_file;

		errcode = pt_elf_add_file(elf, begin, end - begin,
					  offset * pgsz, &ftable, bound);
		if (errcode < 0)
			return errcode;
	}

	return 0;
}

static int pt_elf_read_file_note_32(struct pt_elf *elf, const uint32_t *desc,
				    size_t size)
{
	const char *ftable, *bound;
	uint64_t nentries, pgsz, idx;

	if (!elf || !desc)
		return -pte_internal;

	bound = (const char *) desc + size;

	nentries = *desc++;
	pgsz = *desc++;

	ftable = (const char *) desc + (sizeof(*desc) * 3 * nentries);
	if (bound < ftable)
		return -pte_bad_file;

	for (idx = 0; idx < nentries; ++idx) {
		uint64_t begin, end, offset;
		int errcode;

		begin = *desc++;
		end = *desc++;
		offset = *desc++;

		if (end < begin)
			return -pte_bad_file;

		errcode = pt_elf_add_file(elf, begin, end - begin,
					  offset * pgsz, &ftable, bound);
		if (errcode < 0)
			return errcode;
	}

	return 0;
}

static int pt_elf_read_file_note(struct pt_elf *elf, const void *desc,
				 size_t size)
{
	Elf *libelf;
	size_t addr_size;

	if (!elf)
		return -pte_internal;

	libelf = elf->libelf;
	if (!libelf)
		return -pte_internal;

	addr_size = gelf_fsize(libelf, ELF_T_ADDR, 1, EV_CURRENT);
	switch (addr_size) {
	case 8:
		return pt_elf_read_file_note_64(elf, desc, size);

	case 4:
		return pt_elf_read_file_note_32(elf, desc, size);

	default:
		return -pte_bad_file;
	}
}

static int pt_elf_read_note(struct pt_elf *elf, Elf_Data *data)
{
	size_t noffset;

	if (!elf || !data)
		return -pte_internal;

	noffset = 0;
	for (;;) {
		const uint8_t *desc;
		const char *name;
		GElf_Nhdr nhdr;
		size_t name_offset, desc_offset;
		int errcode;

		noffset = gelf_getnote(data, noffset, &nhdr, &name_offset,
				       &desc_offset);
		if (!noffset)
			break;

		if (data->d_size < (name_offset + nhdr.n_namesz))
			return -pte_bad_file;

		if (data->d_size < (desc_offset + nhdr.n_descsz))
			return -pte_bad_file;

		name = (const char *) data->d_buf + name_offset;

		if (nhdr.n_namesz != sizeof("CORE"))
			continue;

		if (strncmp(name, "CORE", sizeof("CORE")) != 0)
			continue;

		desc = (const uint8_t *) data->d_buf + desc_offset;

		switch (nhdr.n_type) {
		case NT_FILE:
			errcode = pt_elf_read_file_note(elf, desc,
							nhdr.n_descsz);
			if (errcode < 0)
				return errcode;

			break;
		}
	}

	return 0;
}

static int pt_elf_read_note_segment(struct pt_elf *elf, GElf_Phdr *phdr)
{
	Elf_Data *data;

	if (!elf || !phdr)
		return -pte_internal;

	if (!phdr->p_filesz)
		return 0;

	data = elf_getdata_rawchunk(elf->libelf, phdr->p_offset,
				    phdr->p_filesz, ELF_T_NHDR);
	if (!data)
		return -pte_bad_file;

	return pt_elf_read_note(elf, data);
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

		case PT_NOTE:
			errcode = pt_elf_read_note_segment(elf, phdr);
			if (errcode < 0)
				return errcode;

			break;
		}
	}

	return 0;
}

static int pt_elf_read_sections(struct pt_elf *elf)
{
	Elf_Scn *scn;
	Elf *libelf;

	if (!elf)
		return -pte_internal;

	libelf = elf->libelf;
	if (!libelf)
		return -pte_internal;

	scn = NULL;
	for (;;) {
		GElf_Shdr sbuffer, *shdr;
		Elf_Data dbuffer, *data;
		int errcode;

		scn = elf_nextscn(libelf, scn);
		if (!scn)
			break;

		shdr = gelf_getshdr(scn, &sbuffer);
		if (!shdr)
			return -pte_bad_file;

		switch (shdr->sh_type) {
		case SHT_NOTE:
			data = elf_getdata(scn, &dbuffer);
			if (!data)
				break;

			errcode = pt_elf_read_note(elf, data);
			if (errcode < 0)
				return errcode;

			break;
		}
	}

	return 0;
}

static int pt_elf_fixup_external_segments(struct pt_elf *elf)
{
	struct pt_elf_segment *seg;

	if (!elf)
		return -pte_internal;

	for (seg = elf->segments; seg; seg = seg->next) {
		struct pt_elf_file *file;
		uint64_t sbegin, send;

		if (seg->filename)
			continue;

		sbegin = seg->vaddr;
		send = sbegin + seg->size;
		if (send <= sbegin)
			return -pte_internal;

		for (file = elf->files; file; file = file->next) {
			uint64_t fbegin, fend;

			fbegin = file->vaddr;
			fend = fbegin + file->size;
			if (fend < fbegin)
				return -pte_internal;

			if (fbegin <= sbegin && fend == send) {
				char *filename;

				filename = dupstr(file->filename);
				if (!filename)
					return -pte_nomem;

				seg->filename = filename;
				seg->offset = file->offset + (sbegin - fbegin);
			}
		}
	}

	return 0;
}

static int pt_elf_read(struct pt_elf *elf)
{
	int errcode;

	errcode = pt_elf_read_segments(elf);
	if (errcode < 0)
		return errcode;

	errcode = pt_elf_read_sections(elf);
	if (errcode < 0)
		return errcode;

	errcode = pt_elf_fixup_external_segments(elf);
	if (errcode < 0)
		return errcode;

	return 0;
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
	const struct pt_elf_segment *seg;
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

static int pt_elf_is_trace_file(uint32_t *task, const char *filename)
{
	size_t flen;
	int matches, len;

	flen = strnlen(filename, PATH_MAX);
	if (PATH_MAX <= flen)
		return 0;

	matches = sscanf(filename, "/perf/intel_pt:task-%" SCNu32
			 ":%*[^.].event (deleted)%n", task, &len);

	return (matches == 1 && (size_t) len == flen) ? 1 : 0;
}

static int pt_elf_load_file(Elf_Data **pdata, const struct pt_elf *elf,
			    const struct pt_elf_file *file)
{
	const struct pt_elf_segment *seg;
	Elf_Data *data;
	Elf *libelf;

	if (!pdata || !elf || !file)
		return -pte_internal;

	libelf = elf->libelf;
	if (!libelf)
		return -pte_internal;

	if (SIZE_MAX < file->size)
		return -pte_nomem;

	for (seg = elf->segments; seg; seg = seg->next) {

		if (seg->vaddr != file->vaddr ||
		    seg->size != file->size)
			continue;

		if (strcmp(seg->filename, elf->filename) != 0)
			break;

		data = elf_getdata_rawchunk(libelf, (loff_t) seg->offset,
					    (size_t) seg->size, ELF_T_BYTE);
		if (!data)
			return -pte_nomem;

		*pdata = data;

		return 0;
	}

	return -pte_not_supported;
}

#if defined(FEATURE_PEVENT) && defined(PERF_ATTR_SIZE_VER6)

/* The perf note header. */

struct perf_note {
	uint32_t header_size;
	uint32_t pmu_info_size;
};

/* The PMU note for a /perf/intel_pt trace file. */

struct perf_pt_note {
	uint8_t family;
	uint8_t model;
	uint8_t stepping;
	uint8_t nom_freq;
	uint32_t cpuid_0x15_eax;
	uint32_t cpuid_0x15_ebx;
	uint32_t rtit_ctl_high;
	uint64_t addr0_a;
	uint64_t addr0_b;
	uint64_t addr1_a;
	uint64_t addr1_b;
	uint64_t addr2_a;
	uint64_t addr2_b;
	uint64_t addr3_a;
	uint64_t addr3_b;
};

static int pt_elf_read_config(struct pt_config *config,
			      const struct perf_event_attr *attr,
			      const struct perf_pt_note *pmu)
{
	uint32_t ctl;

	if (!config || !attr || !pmu)
		return -pte_internal;

	config->cpu.vendor = pcv_intel;
	config->cpu.family = pmu->family;
	config->cpu.model = pmu->model;
	config->cpu.stepping = pmu->stepping;

	config->cpuid_0x15_eax = pmu->cpuid_0x15_eax;
	config->cpuid_0x15_ebx = pmu->cpuid_0x15_ebx;

	config->mtc_freq = (uint8_t) ((attr->config >> 14) & 0xf);
	config->nom_freq = pmu->nom_freq;

	ctl = pmu->rtit_ctl_high;
	config->addr_filter.config.ctl.addr0_cfg = ctl & 0xf;
	config->addr_filter.config.ctl.addr1_cfg = (ctl >> 4) & 0xf;
	config->addr_filter.config.ctl.addr2_cfg = (ctl >> 8) & 0xf;
	config->addr_filter.config.ctl.addr3_cfg = (ctl >> 12) & 0xf;

	config->addr_filter.addr0_a = pmu->addr0_a;
	config->addr_filter.addr0_b = pmu->addr0_b;
	config->addr_filter.addr1_a = pmu->addr1_a;
	config->addr_filter.addr1_b = pmu->addr1_b;
	config->addr_filter.addr2_a = pmu->addr2_a;
	config->addr_filter.addr2_b = pmu->addr2_b;
	config->addr_filter.addr3_a = pmu->addr3_a;
	config->addr_filter.addr3_b = pmu->addr3_b;

	return 0;
}

static int pt_elf_read_aux(struct pt_config *config, const uint8_t *aux,
			     uint64_t size)
{
	uint8_t *buffer;

	if (!config || !aux)
		return -pte_internal;

	if (SIZE_MAX < size)
		return -pte_nomem;

	buffer = malloc(size);
	if (!buffer)
		return -pte_nomem;

	memcpy(buffer, aux, size);

	config->begin = buffer;
	config->end = buffer + size;

	return 0;
}

static int pt_elf_configure(struct pt_config *config,
			    const struct perf_event_mmap_page *perf,
			    const struct perf_event_attr *attr,
			    const struct perf_pt_note *pmu, uint64_t offset,
			    uint64_t size)
{
	const uint8_t *aux_begin;
	uint64_t aux_offset, aux_size;
	int errcode;

	if (!config || !perf || !pmu)
		return -pte_internal;

	aux_offset = perf->aux_offset;
	aux_size = perf->aux_size;

	if (aux_size < offset)
		return -pte_invalid;

	aux_offset += offset;
	aux_size -= offset;

	if (size && size < aux_size)
		aux_size = size;

	aux_begin = (const uint8_t *) perf + aux_offset;

	errcode = pt_elf_read_config(config, attr, pmu);
	if (errcode < 0)
		return errcode;

	return pt_elf_read_aux(config, aux_begin, aux_size);
}

static int pt_elf_config_trace(struct pt_config *config, Elf_Data *data,
			       uint64_t offset, uint64_t size)
{
	const struct perf_event_mmap_page *perf;
	const struct perf_event_attr *attr;
	const struct perf_pt_note *pmu;
	const struct perf_note *pnote;

	if (!config || !data)
		return -pte_internal;

	if (data->d_size < (offsetof(struct perf_event_mmap_page, pmu_size) +
			    sizeof(perf->pmu_size)))
		return -pte_not_supported;

	perf = (const struct perf_event_mmap_page *) data->d_buf;

	if (data->d_size < (perf->pmu_offset + perf->pmu_size))
		return -pte_bad_file;

	if (perf->pmu_size < PERF_ATTR_SIZE_VER6)
		return -pte_bad_file;

	attr = (const struct perf_event_attr *)
		((const uint8_t *) perf + perf->pmu_offset);

	if (perf->pmu_size < (attr->size + sizeof(*pnote)))
		return -pte_bad_file;

	pnote = (const struct perf_note *)
		((const uint8_t *) attr + attr->size);

	if (perf->pmu_size < (attr->size + pnote->header_size +
			      pnote->pmu_info_size))
		return -pte_bad_file;

	if (pnote->pmu_info_size < sizeof(*pmu))
		return -pte_bad_file;

	pmu = (const struct perf_pt_note *)
		((const uint8_t *) pnote + pnote->header_size);

	if (data->d_size < (perf->aux_offset + perf->aux_size))
		return -pte_bad_file;

	return pt_elf_configure(config, perf, attr, pmu, offset, size);
}

#else /* defined(FEATURE_PEVENT) && defined(PERF_ATTR_SIZE_VER6) */

static int pt_elf_config_trace(struct pt_config *config, Elf_Data *data,
			       uint64_t offset, uint64_t size)
{
	(void) config;
	(void) data;
	(void) offset;
	(void) size;

	return -pte_not_supported;
}

#endif /* defined(FEATURE_PEVENT) && defined(PERF_ATTR_SIZE_VER6) */

static int pt_elf_read_trace(struct pt_config *config, const struct pt_elf *elf,
			     uint64_t offset, uint64_t size, uint32_t utask)
{
	const struct pt_elf_file *file;

	if (!elf)
		return -pte_internal;

	for (file = elf->files; file; file = file->next) {
		Elf_Data *data;
		uint32_t task;
		int errcode;

		if (!pt_elf_is_trace_file(&task, file->filename))
			continue;

		if (task != utask)
			continue;

		errcode = pt_elf_load_file(&data, elf, file);
		if (errcode < 0)
			return errcode;

		return pt_elf_config_trace(config, data, offset, size);
	}

	return -pte_invalid;
}

int pt_elf_load_trace(struct pt_config *config, const char *filename,
		      uint64_t offset, uint64_t size, uint32_t task)
{
	struct pt_elf elf;
	int status;

	status = pt_elf_init(&elf, filename);
	if (status < 0)
		return status;

	status = pt_elf_read(&elf);
	if (status >= 0)
		status = pt_elf_read_trace(config, &elf, offset, size, task);

	pt_elf_fini(&elf);
	return status;
}

int pt_elf_load_core(struct pt_image_section_cache *iscache,
		     struct pt_image *image, struct pt_config *config,
		     const char *filename, uint64_t offset, uint64_t size,
		     uint32_t task, uint32_t flags)
{
	struct pt_elf elf;
	int status;

	status = pt_elf_init(&elf, filename);
	if (status < 0)
		return status;

	status = pt_elf_read(&elf);
	if (status >= 0) {
		status = pt_elf_read_trace(config, &elf, offset, size, task);
		if (status >= 0)
			status = pt_elf_add_segments(iscache, image, &elf,
						     0ull, flags);
	}

	pt_elf_fini(&elf);
	return status;

}

static int pt_elf_print_tasks(FILE *stream, const struct pt_elf *elf)
{
	const struct pt_elf_file *file;
	int ntasks;

	if (!stream || !elf)
		return -pte_internal;

	ntasks = 0;
	for (file = elf->files; file; file = file->next) {
		uint32_t task;

		if (!pt_elf_is_trace_file(&task, file->filename))
			continue;

		if (ntasks++)
			fprintf(stream, " ");
		fprintf(stream, "%" PRIu32, task);
	}

	if (ntasks)
		fprintf(stream, "\n");

	return ntasks;
}

int pt_elf_print_tasks_with_trace(FILE *stream, const char *filename)
{
	struct pt_elf elf;
	int status;

	status = pt_elf_init(&elf, filename);
	if (status < 0)
		return status;

	status = pt_elf_read(&elf);
	if (status >= 0)
		status = pt_elf_print_tasks(stream, &elf);

	pt_elf_fini(&elf);
	return status;
}
