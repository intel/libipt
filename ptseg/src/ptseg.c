/*
 * Copyright (c) 2018-2022, Intel Corporation
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

#include "pt_version.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


static int help(const char *ptseg)
{
	printf("usage: %s [<options>] <ptfile>:<offset>\n\n", ptseg);
	printf("options:\n");
	printf("  --help|-h          this text.\n");
	printf("  --version          display version information and exit.\n");

	return 0;
}

static int usage(const char *ptseg)
{
	help(ptseg);

	return 1;
}

static int version(const char *ptseg)
{
	pt_print_tool_version(ptseg);

	return 0;
}

static int internal_error(const char *ptseg)
{
	fprintf(stderr, "%s: internal error.\n", ptseg);

	return 1;
}

static int bad_option(const char *ptseg, const char *arg)
{
	fprintf(stderr, "%s: unknown option: %s.\n", ptseg, arg);

	return 1;
}

static int no_ptfile(const char *ptseg)
{
	fprintf(stderr, "%s: missing ptfile.\n", ptseg);

	return 1;
}

static int trailing_junk(const char *ptseg, const char *arg)
{
	fprintf(stderr, "%s: trailing junk: %s.\n", ptseg, arg);

	return 1;
}

static int no_filename(const char *ptseg, const char *arg)
{
	fprintf(stderr, "%s: missing file name: %s.\n", ptseg, arg);

	return 1;
}

static int no_offset(const char *ptseg, const char *arg)
{
	fprintf(stderr, "%s: missing file offset: %s.\n", ptseg, arg);

	return 1;
}

static int bad_offset(const char *ptseg, const char *arg)
{
	fprintf(stderr, "%s: bad file offset: %s.\n", ptseg, arg);

	return 1;
}

static int decode_error(const char *ptseg, int errcode)
{
	fprintf(stderr, "%s: decode error: %s.\n", ptseg,
		pt_errstr(pt_errcode(errcode)));

	return -errcode;
}

static int load_file(uint8_t **buffer, size_t *psize, const char *filename,
		     uint64_t offset, uint64_t size, const char *ptseg)
{
	uint8_t *content;
	size_t read;
	FILE *file;
	long fsize, begin, end;
	int errcode;

	if (!buffer || !psize || !filename)
		return internal_error(ptseg);

	errno = 0;
	file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "%s: failed to open %s: %d.\n",
			ptseg, filename, errno);
		return -1;
	}

	errcode = fseek(file, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			ptseg, filename, errno);
		goto err_file;
	}

	fsize = ftell(file);
	if (fsize < 0) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			ptseg, filename, errno);
		goto err_file;
	}

	begin = (long) offset;
	if (((uint64_t) begin != offset) || (fsize <= begin)) {
		fprintf(stderr,
			"%s: bad offset 0x%" PRIx64 " into %s.\n",
			ptseg, offset, filename);
		goto err_file;
	}

	end = fsize;
	if (size) {
		uint64_t range_end;

		range_end = offset + size;
		if ((uint64_t) end < range_end) {
			fprintf(stderr,
				"%s: bad range 0x%" PRIx64 " in %s.\n",
				ptseg, range_end, filename);
			goto err_file;
		}

		end = (long) range_end;
	}

	fsize = end - begin;

	content = malloc((size_t) fsize);
	if (!content) {
		fprintf(stderr, "%s: failed to allocated memory %s.\n",
			ptseg, filename);
		goto err_file;
	}

	errcode = fseek(file, begin, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			ptseg, filename, errno);
		goto err_content;
	}

	read = fread(content, (size_t) fsize, 1u, file);
	if (read != 1) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			ptseg, filename, errno);
		goto err_content;
	}

	fclose(file);

	*buffer = content;
	*psize = (size_t) fsize;

	return 0;

err_content:
	free(content);

err_file:
	fclose(file);
	return -1;
}

static int ptseg_pkt_find_seg(uint64_t *begin, uint64_t *end,
			      struct pt_packet_decoder *decoder,
			      uint64_t offset)
{
	int errcode;

	errcode = pt_pkt_sync_set(decoder, offset);
	if (errcode < 0)
		return errcode;

	errcode = pt_pkt_sync_backward(decoder);
	if (errcode < 0) {
		if (errcode != -pte_eos)
			return errcode;
	} else {
		errcode = pt_pkt_get_offset(decoder, begin);
		if (errcode < 0)
			return errcode;
	}

	errcode = pt_pkt_sync_forward(decoder);
	if (errcode < 0) {
		if (errcode != -pte_eos)
			return errcode;
	} else {
		errcode = pt_pkt_get_offset(decoder, end);
		if (errcode < 0)
			return errcode;
	}

	return 0;
}

static int ptseg_find_seg(uint64_t *begin, uint64_t *end,
			  const struct pt_config *config, uint64_t offset)
{
	struct pt_packet_decoder *decoder;
	int errcode;

	decoder = pt_pkt_alloc_decoder(config);
	if (!decoder)
		return -pte_nomem;

	errcode = ptseg_pkt_find_seg(begin, end, decoder, offset);

	pt_pkt_free_decoder(decoder);

	return errcode;
}

static int ptseg_print_seg(const char *ptfile, uint64_t offset,
			   const char *ptseg)
{
	struct pt_config config;
	uint64_t begin, end;
	uint8_t *buffer;
	size_t size;
	int errcode;

	errcode = load_file(&buffer, &size, ptfile, 0ull, 0ull, ptseg);
	if (errcode)
		return errcode;

	pt_config_init(&config);
	config.begin = buffer;
	config.end = buffer + size;

	begin = 0ull;
	end = size;

	errcode = ptseg_find_seg(&begin, &end, &config, offset);

	free(buffer);

	if (errcode < 0)
		return decode_error(ptseg, errcode);

	printf("0x%" PRIx64 "-0x%" PRIx64 " (offset: 0x%" PRIx64 ", size: 0x%"
	       PRIx64 ")\n", begin, end, offset - begin, end - begin);

	return 0;
}

static int ptseg_split_ptarg(const char **ptfile, uint64_t *ptoffset,
			     char *ptarg, const char *ptseg)
{
	char *psep, *rest;

	if (!ptfile || !ptoffset || !ptarg)
		return internal_error(ptseg);

	/* Search from the end as the filename may also contain ':'. */
	psep = strrchr(ptarg, ':');
	if (!psep)
		return no_offset(ptseg, ptarg);

	if (psep == ptarg)
		return no_filename(ptseg, ptarg);

	*ptfile = ptarg;
	*psep++ = 0;

	errno = 0;
	*ptoffset = (uint64_t) strtoull(psep, &rest, 0);
	if (errno || *rest)
		return bad_offset(ptseg, psep);

	return 0;
}

extern int main(int argc, char *argv[])
{
	const char *ptseg, *ptfile;
	char *arg, *ptarg;
	uint64_t ptoffset;
	int errcode;

	(void) argc;
	if (!argv)
		return usage("");

	ptseg = *argv++;
	if (!ptseg)
		return usage("");

	arg = *argv++;
	if (!arg)
		return no_ptfile(ptseg);

	if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0)
		return help(ptseg);

	if (strcmp(arg, "--version") == 0)
		return version(ptseg);

	if (arg[0] == '-')
		return bad_option(ptseg, arg);

	ptarg = arg;
	arg = *argv++;
	if (arg)
		return trailing_junk(ptseg, arg);

	ptfile = NULL;
	ptoffset = 0ull;
	errcode = ptseg_split_ptarg(&ptfile, &ptoffset, ptarg, ptseg);
	if (errcode)
		return -errcode;

	return ptseg_print_seg(ptfile, ptoffset, ptseg);
}
