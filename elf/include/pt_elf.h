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

#ifndef PT_ELF_H
#define PT_ELF_H

#include <stdint.h>
#include <stdio.h>

struct pt_image_section_cache;
struct pt_image;
struct pt_config;


/* A collection of flags. */
enum pt_elf_flags {
	/* Print information about loaded segments. */
	pte_verbose	= 1 << 0
};

/* Load executable segments from an ELF file.
 *
 * Adds a section to @image for each executable segment in @filename.
 *
 * If @base is non-zero, the load addresses are modified such that the first
 * segment is loaded at @base.
 *
 * If pte_verbose is set in @flags, prints information about the loaded segments
 * to stdout.
 *
 * If @iscache is not NULL, adds sections to @iscache and from there to @image.
 *
 * If @sysroot is not NULL, prepends it to sections added from file notes.
 *
 * Returns the number of added image sections on success, a negative
 * pt_error_code otherwise.
 * Returns -pte_internal if @image or @filename is NULL.
 * Returns -pte_bad_file if @filename is not an ELF file.
 * Returns -pte_nomem if not enough memory can be allocated.
 */
extern int pt_elf_load_segments(struct pt_image_section_cache *iscache,
				struct pt_image *image, const char *filename,
				uint64_t base, const char *sysroot,
				uint32_t flags);

/* Load trace from a coredump note of an ELF file.
 *
 * Searches for a /perf/intel_pt-task:@task file in @filename's NT_FILE notes
 * and, if found, copies the trace data and the PMU configuration into @config.
 *
 * The caller is responsible for freeing the trace buffer.
 *
 * If @offset is non-zero, skips @offset bytes at the beginning of the trace.
 * If @size is non-zero, copies at most @size bytes of trace data.
 *
 * Returns 0 on success, a negative pt_error_code otherwise.
 * Returns -pte_internal if @config or @filename is NULL.
 * Returns -pte_invalid if @filename does not contain trace for @task.
 * Returns -pte_invalid if @offset is outside the bounds of the trace.
 * Returns -pte_bad_file if @filename is not an ELF file.
 * Returns -pte_not_supported if the feature is not supported.
 * Returns -pte_nomem if not enough memory can be allocated.
 */
extern int pt_elf_load_trace(struct pt_config *config, const char *filename,
			     uint64_t offset, uint64_t size, uint32_t task);

/* Load trace and executable segments from a coredump note of an ELF file.
 *
 * Searches for a /perf/intel_pt-task:@task file in @filename's NT_FILE notes
 * and, if found, copies the trace data and the PMU configuration into @config.
 *
 * The caller is responsible for freeing the trace buffer.
 *
 * If @offset is non-zero, skips @offset bytes at the beginning of the trace.
 * If @size is non-zero, copies at most @size bytes of trace data.
 *
 * Adds a section to @image for each executable segment in @filename.
 *
 * If pte_verbose is set in @flags, prints information about the loaded segments
 * to stdout.
 *
 * If @iscache is not NULL, adds sections to @iscache and from there to @image.
 *
 * If @sysroot is not NULL, prepends it to sections added from file notes.
 *
 * Returns 0 on success, a negative pt_error_code otherwise.
 * Returns -pte_internal if @config or @filename is NULL.
 * Returns -pte_invalid if @filename does not contain trace for @task.
 * Returns -pte_invalid if @offset is outside the bounds of the trace.
 * Returns -pte_bad_file if @filename is not an ELF file.
 * Returns -pte_not_supported if the feature is not supported.
 * Returns -pte_nomem if not enough memory can be allocated.
 */
extern int pt_elf_load_core(struct pt_image_section_cache *iscache,
			    struct pt_image *image, struct pt_config *config,
			    const char *filename, uint64_t offset,
			    uint64_t size, const char *sysroot, uint32_t task,
			    uint32_t flags);

/* Print tasks for which trace is available in @filename into @stream.
 *
 * Returns the number of tasks that were printed on success, a negative
 * pt_error_code otherwise.
 * Returns -pte_internal if @stream or @filename is NULL.
 * Returns -pte_bad_file if @filename is not an ELF file.
 * Returns -pte_not_supported if the feature is not supported.
 */
extern int pt_elf_print_tasks_with_trace(FILE *stream, const char *filename);

#endif /* PT_ELF_H */
