/*
 * Copyright (C) 2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
#include "ptunit_mkfile.h"

#include "pt_sb_file.h"

#include "libipt-sb.h"

#include <stdlib.h>


/* A test fixture providing a temporary file and buffer. */
struct file_fixture {
	/* A temporary file name. */
	char *name;

	/* That file opened for writing. */
	FILE *file;

	/* A heap-allocated buffer. */
	void *buffer;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct file_fixture *);
	struct ptunit_result (*fini)(struct file_fixture *);
};

static struct ptunit_result ffix_init(struct file_fixture *ffix)
{
	int errcode;

	ffix->file = NULL;
	ffix->name = NULL;
	ffix->buffer = NULL;

	errcode = ptunit_mkfile(&ffix->file, &ffix->name, "wb");
	ptu_int_eq(errcode, 0);

	return ptu_passed();
}

static struct ptunit_result ffix_fini(struct file_fixture *ffix)
{
	char *filename;
	FILE *file;
	void *buffer;
	int errcode;

	filename = ffix->name;
	file = ffix->file;
	buffer = ffix->buffer;

	ffix->name = NULL;
	ffix->file = NULL;
	ffix->buffer = NULL;

	/* Try removing the file while we still have it open to avoid races
	 * with others re-using the temporary filename.
	 *
	 * On some systems that may not be possible and we can choose between:
	 *
	 *   - guaranteed leaking files or
	 *   - running the risk of removing someone elses file
	 *
	 * We choose the latter.  Assuming those systems behave consistently,
	 * removing someone elses file should only succeed if it isn't open at
	 * the moment we try removing it.  Given that this is a temporary file,
	 * we should be able to rule out accidental name clashes with
	 * non-temporary files.
	 */
	if (filename && file) {
		errcode = remove(filename);
		if (!errcode) {
			free(filename);
			filename = NULL;
		}
	}

	if (file)
		fclose(file);

	if (filename) {
		(void) remove(filename);
		free(filename);
	}

	free(buffer);

	return ptu_passed();
}

static struct ptunit_result ffix_write_aux(struct file_fixture *ffix,
					   const uint8_t *buffer, size_t size)
{
	size_t written;

	written = fwrite(buffer, 1, size, ffix->file);
	ptu_uint_eq(written, size);

	fflush(ffix->file);

	return ptu_passed();
}

#define ffix_write(ffix, buffer)				\
	ptu_check(ffix_write_aux, ffix, buffer, sizeof(buffer))

static struct ptunit_result begin_past_end(struct file_fixture *ffix)
{
	uint8_t bytes[] = { 0x0 };
	size_t size;
	int errcode;

	ffix_write(ffix, bytes);

	errcode = pt_sb_file_load(&ffix->buffer, &size, ffix->name,
				  sizeof(bytes) + 1, sizeof(bytes));
	ptu_int_eq(errcode, -pte_invalid);
	ptu_null(ffix->buffer);

	errcode = pt_sb_file_load(&ffix->buffer, &size, ffix->name,
				  sizeof(bytes) + 1, 0);
	ptu_int_eq(errcode, -pte_bad_file);
	ptu_null(ffix->buffer);

	return ptu_passed();
}

static struct ptunit_result begin_at_end(struct file_fixture *ffix)
{
	uint8_t bytes[] = { 0x0 };
	size_t size;
	int errcode;

	ffix_write(ffix, bytes);

	errcode = pt_sb_file_load(&ffix->buffer, &size, ffix->name,
				  sizeof(bytes), sizeof(bytes));
	ptu_int_eq(errcode, -pte_invalid);
	ptu_null(ffix->buffer);

	errcode = pt_sb_file_load(&ffix->buffer, &size, ffix->name,
				  sizeof(bytes), 0);
	ptu_int_eq(errcode, -pte_bad_file);
	ptu_null(ffix->buffer);

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct file_fixture ffix;
	struct ptunit_suite suite;

	ffix.init = ffix_init;
	ffix.fini = ffix_fini;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run_f(suite, begin_past_end, ffix);
	ptu_run_f(suite, begin_at_end, ffix);

	return ptunit_report(&suite);
}
