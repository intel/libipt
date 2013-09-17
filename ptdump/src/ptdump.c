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

#include "pt_print.h"

#include "pt_packet.h"
#include "pt_decode.h"
#include "pt_last_ip.h"
#include "pt_config.h"
#include "pt_error.h"
#include "pt_version.h"

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#if defined(FEATURE_MMAP)
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <fcntl.h>
# include <unistd.h>
#endif


enum pt_dump_flag {
	/* Show the current offset in the trace stream. */
	ptd_show_offset = 1 << 0,

	/* Show raw packet bytes. */
	ptd_show_raw_bytes = 1 << 1,

	/* Show last IP for packets with IP payloads. */
	ptd_show_last_ip = 1 << 2,

	/* Print current offset column always with fixed width. */
	ptd_fixed_offset_width = 1 << 3,
};


static int usage(const char *name)
{
	fprintf(stderr,
		"%s: [<options>] <ptfile>.  Use --help or -h for help.\n",
		name);
	return -1;
}

static int no_file_error(const char *name)
{
	fprintf(stderr, "%s: No processor trace file specified.\n", name);
	return -1;
}

static int help(const char *name)
{
	fprintf(stderr,
		"usage: %s [<options>] <ptfile>\n\n"
		"options:\n"
		"  --help|-h              this text.\n"
		"  --version              display version information and exit.\n"
		"  --no-offset            don't show the offset as the first column.\n"
		"  --raw                  show raw packet bytes.\n"
		"  --lastip               show last IP updates on packets with IP payloads.\n"
		"  --fixed-offset-width   assume fixed width of 16 characters for the\n"
		"                         offset column.\n",
		name);

	return 0;
}

static int version(const char *name)
{
	struct pt_version v = pt_library_version();

	printf("%s-%u.%u.%u%s / libipt-%u.%u.%u%s\n", name,
	       PT_VERSION_MAJOR, PT_VERSION_MINOR, PT_VERSION_BUILD,
	       PT_VERSION_EXT, v.major, v.minor, v.build, v.ext);
	return 0;
}

#if defined(FEATURE_MMAP)

static void *map_pt(const char *file, uint32_t *size)
{
	struct stat stat;
	int fd, errcode;
	void *pt;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", file,
			strerror(errno));
		return NULL;
	}

	errcode = fstat(fd, &stat);
	if (errcode) {
		fprintf(stderr, "failed to fstat %s: %s\n", file,
			strerror(errno));
		close(fd);
		return NULL;
	}

	pt = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (pt == MAP_FAILED) {
		fprintf(stderr, "failed to mmap %s: %s\n", file,
			strerror(errno));
		close(fd);
		return NULL;
	}

	if (size)
		*size = stat.st_size;

	close(fd);
	return pt;
}

#else /* defined(FEATURE_MMAP) */

static void *map_pt(const char *file, uint32_t *size)
{
	FILE *fd;
	uint32_t fsize;
	int errcode;
	long pos;
	void *pt;
	size_t read;

	errno = 0;
	fd = fopen(file, "rb");
	if (!fd) {
		fprintf(stderr, "%s: cannot open: %s\n", file, strerror(errno));
		return NULL;
	}

	errcode = fseek(fd, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to seek end: %s\n", file,
			strerror(errno));
		fclose(fd);
		return NULL;
	}

	pos = ftell(fd);
	if (pos < 0) {
		fprintf(stderr, "%s: failed to determine file size: %s\n",
			file, strerror(errno));
		fclose(fd);
		return NULL;
	}
	if (pos == 0) {
		fprintf(stderr, "%s: file empty\n", file);
		fclose(fd);
		return NULL;
	}
	fsize = (size_t) pos;

	errcode = fseek(fd, 0, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to seek begin: %s\n", file,
			strerror(errno));
		fclose(fd);
		return NULL;
	}

	pt = malloc(fsize);
	if (!pt) {
		fprintf(stderr,
			"%s: failed to allocate %" PRIu32 " bytes: %s\n",
			file, fsize, strerror(errno));
		fclose(fd);
		return NULL;
	}

	read = fread(pt, 1, fsize, fd);

	errcode = ferror(fd);
	if (errcode) {
		fprintf(stderr, "%s: failed to read file: %s\n", file,
			strerror(errcode));
		fclose(fd);
		free(pt);
		return NULL;
	}

	if (size)
		*size = (uint32_t) read;

	fclose(fd);
	return pt;
}

#endif /* defined(FEATURE_MMAP) */

static inline unsigned calc_col_offset_width(uint64_t highest_val)
{
	int idx = 63;
	for (idx = 63; idx > 0; --idx)
		if (highest_val & (1ull << idx))
			break;
	return 1 + (idx / 4);
}

static inline void print_col_separator(FILE *f)
{
	fprintf(f, "  ");
}

static inline void fillup_column(FILE *f, unsigned actual_width,
				 unsigned col_width)
{
	if (actual_width >= col_width)
		return;
	fprintf(f, "%*c", col_width - actual_width, ' ');
}

static int dump(uint8_t *begin, uint8_t *end, uint32_t flags, FILE *f)
{
	int errcode;
	struct pt_packet packet;
	struct pt_config config;
	struct pt_decoder *decoder;
	struct pt_last_ip last_ip;
	char str[pps_payload];
	int ret;

	unsigned col_offset_width_used = 0;
	unsigned col_packettype_width_used = 0;
	unsigned col_payload_width_used = 0;

	const unsigned col_offset_width_fixed = 16;
	const unsigned col_offset_width = (flags & ptd_fixed_offset_width) ?
		col_offset_width_fixed :
		calc_col_offset_width(end - begin);
	const unsigned col_packettype_width = 9;
	const unsigned col_payload_width = 47;

	errcode = 0;

	memset(&packet, 0, sizeof(packet));

	memset(&config, 0, sizeof(config));
	pt_configure(&config);
	config.begin = begin;
	config.end = end;

	decoder = NULL;
	decoder = pt_alloc_decoder(&config);
	if (!decoder) {
		fprintf(stderr, "*** ERROR: allocate decoder.\n");
		errcode = -pte_nomem;
		goto out;
	}

	pt_last_ip_init(&last_ip);


	/* Sync to the stream. */
	errcode = pt_sync_forward(decoder);
	if (errcode < 0) {
		fprintf(stderr,
			"*** ERROR: syncing to the trace stream failed "
			"(libipt error: %s).\n",
			pt_errstr(pt_errcode(errcode)));
		goto out;
	}

	for (;;) {
		/* Decode packet. */
		ret = pt_decode(&packet, decoder);
		if (pt_errcode(ret) == pte_eos)
			goto out;
		else if (pt_errcode(ret) != pte_ok) {
			fprintf(stderr,
				"*** ERROR: packet decoding failed "
				"(libipt error: %s).\n",
				pt_errstr(pt_errcode(ret)));
			errcode = ret;
			goto out;
		}
		if (packet.size == 0) {
			fprintf(stderr,
				"*** ERROR: packet decoding failed, "
				"packet size is reported to be 0.\n");
			errcode = -pte_bad_packet;
			goto out;
		}

		/* Print stream offset. */
		if (flags & ptd_show_offset) {
			ret = fprintf(f, "%0*" PRIx64, col_offset_width,
				      pt_get_decoder_pos(decoder));
			if (ret <= 0) {
				fprintf(stderr,
					"*** ERROR: having problems with "
					"printing the offset.\n");
				errcode = -pte_internal;
				goto out;
			}
			col_offset_width_used = ret;

			fillup_column(f,
				col_offset_width_used, col_offset_width);
			print_col_separator(f);
		}

		/* Print packet type. */
		ret = fprintf(f, "%s", pt_print_packet_type_str(&packet));
		if (ret <= 0) {
			fprintf(stderr,
				"\n*** ERROR: having problems with printing "
				"the packet type.\n");
			errcode = -pte_internal;
			goto out;
		}
		col_packettype_width_used = ret;

		/* Print the packet payload. */
		ret = pt_print_fill_payload_str(str, sizeof(str), &packet);
		if (ret < 0) {
			fprintf(stderr,
				"\n*** ERROR: having problems with printing "
				"the payload.\n");
			errcode = -pte_internal;
			goto out;
		}
		if (ret > 0) {
			fillup_column(f,
				col_packettype_width_used,
				col_packettype_width);
			print_col_separator(f);
		}
		col_payload_width_used = fprintf(f, "%s", str);

		/* Print last IP if requested
		 * and if packet type is an IP packet. */
		if (flags & ptd_show_last_ip) {
			uint64_t ip;

			switch (packet.type) {
			case ppt_tip:
			case ppt_tip_pge:
			case ppt_tip_pgd:
			case ppt_fup:
				ret = pt_last_ip_update_ip(&last_ip,
							   &packet.payload.ip,
							   &config);

				if (ret == -pte_invalid) {
					fprintf(stderr,
						"\n*** ERROR: "
						"internal error.\n");
					errcode = -pte_internal;
					goto out;
				}
				if (ret == -pte_bad_packet) {
					fprintf(stderr,
						"\n*** ERROR: "
						"malformed packet.\n");
					errcode = -pte_bad_packet;
					goto out;
				}
				if (ret == -pte_noip)
					goto skip_last_ip_printing;

				break;
			default:
				goto skip_last_ip_printing;
				break;
			}

			ret = pt_last_ip_query(&ip, &last_ip);
			if (ret == -pte_invalid) {
				fprintf(stderr,
					"\n*** ERROR: internal error.\n");
				errcode = -pte_internal;
				goto out;
			}
			if (ret == -pte_noip)
				goto skip_last_ip_printing;
			if (ret == -pte_ip_suppressed)
				ret = fprintf(f, ", ip=<suppressed>");
			if (ret == 0)
				ret = fprintf(f, ", ip=0x%016" PRIx64, ip);
			if (ret < 0) {
				fprintf(stderr,
					"\n*** ERROR: having problems "
					"with printing the last IP.\n");
				return -pte_internal;
			}
			col_payload_width_used += ret;
		}
skip_last_ip_printing:

		/* Print raw packet bytes. */
		if (flags & ptd_show_raw_bytes) {
			uint8_t idx;

			if (col_payload_width_used == 0) {
				fillup_column(f,
					col_packettype_width_used,
					col_packettype_width);
				print_col_separator(f);
			}

			fillup_column(f,
				col_payload_width_used, col_payload_width);
			print_col_separator(f);

			fprintf(f, "[");
			for (idx = 0; idx < packet.size; ++idx) {
				uint8_t u;

				u = *(pt_get_decoder_raw(decoder) + idx);
				fprintf(f, "%02x", (unsigned)u);
				if (idx != (packet.size - 1))
					fprintf(f, " ");
			}
			fprintf(f, "]");
		}

		/* End of information printing for this packet. */
		fprintf(f, "\n");

		/* Go to next packet. */
		pt_advance(decoder, packet.size);
	}

out:
	pt_free_decoder(decoder);
	return errcode;
}

int main(int argc, const char **argv)
{
	uint32_t flags, size;
	uint8_t *pt;
	int errcode, idx;
	const char *ptfile;

	ptfile = NULL;
	flags = ptd_show_offset;

	for (idx = 1; idx < argc; ++idx) {
		if (strncmp(argv[idx], "-", 1) != 0) {
			ptfile = argv[idx];
			if (idx < (argc-1))
				return usage(argv[0]);
			break;
		}

		if (strcmp(argv[idx], "-h") == 0)
			return help(argv[0]);
		if (strcmp(argv[idx], "--help") == 0)
			return help(argv[0]);
		if (strcmp(argv[idx], "--version") == 0)
			return version(argv[0]);
		else if (strcmp(argv[idx], "--no-offset") == 0)
			flags &= ~ptd_show_offset;
		else if (strcmp(argv[idx], "--raw") == 0)
			flags |= ptd_show_raw_bytes;
		else if (strcmp(argv[idx], "--lastip") == 0)
			flags |= ptd_show_last_ip;
		else if (strcmp(argv[idx], "--fixed-offset-width") == 0)
			flags |= ptd_fixed_offset_width;
		else
			return usage(argv[0]);
	}

	if (!ptfile)
		return no_file_error(argv[0]);

	/* We will leak the pt buffer. */
	pt = map_pt(ptfile, &size);
	if (!pt) {
		fprintf(stderr, "Failed to read PT stream.\n");
		return -1;
	}

	errcode = dump(pt, pt + size, flags, stdout);

	return -errcode;
}
