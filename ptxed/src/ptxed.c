/*
 * Copyright (c) 2013-2016, Intel Corporation
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

#if defined(FEATURE_ELF)
# include "load_elf.h"
#endif /* defined(FEATURE_ELF) */

#include "pt_cpu.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include <xed-interface.h>


/* The type of decoder to be used. */
enum ptxed_decoder_type {
	pdt_insn_decoder,
	pdt_block_decoder
};

/* The decoder to use. */
struct ptxed_decoder {
	/* The decoder type. */
	enum ptxed_decoder_type type;

	/* The actual decoder. */
	union {
		/* If @type == pdt_insn_decoder */
		struct pt_insn_decoder *insn;

		/* If @type == pdt_block_decoder */
		struct pt_block_decoder *block;
	} variant;
};

/* A collection of options. */
struct ptxed_options {
	/* Do not print the instruction. */
	uint32_t dont_print_insn:1;

	/* Remain as quiet as possible - excluding error messages. */
	uint32_t quiet:1;

	/* Print statistics (overrides quiet). */
	uint32_t print_stats:1;

	/* Print information about section loads and unloads. */
	uint32_t track_image:1;

	/* Print in AT&T format. */
	uint32_t att_format:1;

	/* Print the offset into the trace file. */
	uint32_t print_offset:1;

	/* Print the raw bytes for an insn. */
	uint32_t print_raw_insn:1;
};

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;
};

static int ptxed_have_decoder(const struct ptxed_decoder *decoder)
{
	/* It suffices to check for one decoder in the variant union. */
	return decoder && decoder->variant.insn;
}

static void ptxed_free_decoder(struct ptxed_decoder *decoder)
{
	if (!decoder)
		return;

	switch (decoder->type) {
	case pdt_insn_decoder:
		pt_insn_free_decoder(decoder->variant.insn);
		break;

	case pdt_block_decoder:
		pt_blk_free_decoder(decoder->variant.block);
		break;
	}
}

static void version(const char *name)
{
	struct pt_version v = pt_library_version();

	printf("%s-%d.%d.%d%s / libipt-%" PRIu8 ".%" PRIu8 ".%" PRIu32 "%s\n",
	       name, PT_VERSION_MAJOR, PT_VERSION_MINOR, PT_VERSION_BUILD,
	       PT_VERSION_EXT, v.major, v.minor, v.build, v.ext);
}

static void help(const char *name)
{
	printf("usage: %s [<options>]\n\n"
	       "options:\n"
	       "  --help|-h                     this text.\n"
	       "  --version                     display version information and exit.\n"
	       "  --att                         print instructions in att format.\n"
	       "  --no-inst                     do not print instructions (only addresses).\n"
	       "  --quiet|-q                    do not print anything (except errors).\n"
	       "  --offset                      print the offset into the trace file.\n"
	       "  --raw-insn                    print the raw bytes of each instruction.\n"
	       "  --stat                        print statistics (even when quiet).\n"
	       "  --verbose|-v                  print various information (even when quiet).\n"
	       "  --pt <file>[:<from>[-<to>]]   load the processor trace data from <file>.\n"
	       "                                an optional offset or range can be given.\n"
#if defined(FEATURE_ELF)
	       "  --elf <<file>[:<base>]        load an ELF from <file> at address <base>.\n"
	       "                                use the default load address if <base> is omitted.\n"
#endif /* defined(FEATURE_ELF) */
	       "  --raw <file>:<base>           load a raw binary from <file> at address <base>.\n"
	       "  --cpu none|auto|f/m[/s]       set cpu to the given value and decode according to:\n"
	       "                                  none     spec (default)\n"
	       "                                  auto     current cpu\n"
	       "                                  f/m[/s]  family/model[/stepping]\n"
	       "  --mtc-freq <n>                set the MTC frequency (IA32_RTIT_CTL[17:14]) to <n>.\n"
	       "  --nom-freq <n>                set the nominal frequency (MSR_PLATFORM_INFO[15:8]) to <n>.\n"
	       "  --cpuid-0x15.eax              set the value of cpuid[0x15].eax.\n"
	       "  --cpuid-0x15.ebx              set the value of cpuid[0x15].ebx.\n"
	       "  --insn-decoder                use the instruction flow decoder (default).\n"
	       "  --block-decoder               use the block decoder.\n"
	       "\n"
#if defined(FEATURE_ELF)
	       "You must specify at least one binary or ELF file (--raw|--elf).\n"
#else /* defined(FEATURE_ELF) */
	       "You must specify at least one binary file (--raw).\n"
#endif /* defined(FEATURE_ELF) */
	       "You must specify exactly one processor trace file (--pt).\n",
	       name);
}

static int extract_base(char *arg, uint64_t *base)
{
	char *sep, *rest;

	sep = strrchr(arg, ':');
	if (sep) {
		uint64_t num;

		if (!sep[1])
			return 0;

		errno = 0;
		num = strtoull(sep+1, &rest, 0);
		if (errno || *rest)
			return 0;

		*base = num;
		*sep = 0;
		return 1;
	}

	return 0;
}

static int parse_range(const char *arg, uint64_t *begin, uint64_t *end)
{
	char *rest;

	if (!arg || !*arg)
		return 0;

	errno = 0;
	*begin = strtoull(arg, &rest, 0);
	if (errno)
		return -1;

	if (!*rest)
		return 1;

	if (*rest != '-')
		return -1;

	*end = strtoull(rest+1, &rest, 0);
	if (errno || *rest)
		return -1;

	return 2;
}

static int load_file(uint8_t **buffer, size_t *size, char *arg,
		     const char *prog)
{
	uint64_t begin_arg, end_arg;
	uint8_t *content;
	size_t read;
	FILE *file;
	long fsize, begin, end;
	int errcode, range_parts;
	char *range;

	if (!buffer || !size || !arg || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
		return -1;
	}

	range_parts = 0;
	begin_arg = 0ull;
	end_arg = UINT64_MAX;

	range = strrchr(arg, ':');
	if (range) {
		/* Let's try to parse an optional range suffix.
		 *
		 * If we can, remove it from the filename argument.
		 * If we can not, assume that the ':' is part of the filename,
		 * e.g. a drive letter on Windows.
		 */
		range_parts = parse_range(range + 1, &begin_arg, &end_arg);
		if (range_parts <= 0) {
			begin_arg = 0ull;
			end_arg = UINT64_MAX;

			range_parts = 0;
		} else
			*range = 0;
	}

	errno = 0;
	file = fopen(arg, "rb");
	if (!file) {
		fprintf(stderr, "%s: failed to open %s: %d.\n",
			prog, arg, errno);
		return -1;
	}

	errcode = fseek(file, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, arg, errno);
		goto err_file;
	}

	fsize = ftell(file);
	if (fsize < 0) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, arg, errno);
		goto err_file;
	}

	/* Truncate the range to fit into the file unless an explicit range end
	 * was provided.
	 */
	if (range_parts < 2)
		end_arg = (uint64_t) fsize;

	begin = (long) begin_arg;
	end = (long) end_arg;
	if ((uint64_t) begin != begin_arg || (uint64_t) end != end_arg) {
		fprintf(stderr, "%s: invalid offset/range argument.\n", prog);
		goto err_file;
	}

	if (fsize <= begin) {
		fprintf(stderr, "%s: offset 0x%lx outside of %s.\n",
			prog, begin, arg);
		goto err_file;
	}

	if (fsize < end) {
		fprintf(stderr, "%s: range 0x%lx outside of %s.\n",
			prog, end, arg);
		goto err_file;
	}

	if (end <= begin) {
		fprintf(stderr, "%s: bad range.\n", prog);
		goto err_file;
	}

	fsize = end - begin;

	content = malloc(fsize);
	if (!content) {
		fprintf(stderr, "%s: failed to allocated memory %s.\n",
			prog, arg);
		goto err_file;
	}

	errcode = fseek(file, begin, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, arg, errno);
		goto err_content;
	}

	read = fread(content, fsize, 1, file);
	if (read != 1) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, arg, errno);
		goto err_content;
	}

	fclose(file);

	*buffer = content;
	*size = fsize;

	return 0;

err_content:
	free(content);

err_file:
	fclose(file);
	return -1;
}

static int load_pt(struct pt_config *config, char *arg, const char *prog)
{
	uint8_t *buffer;
	size_t size;
	int errcode;

	errcode = load_file(&buffer, &size, arg, prog);
	if (errcode < 0)
		return errcode;

	config->begin = buffer;
	config->end = buffer + size;

	return 0;
}

static int load_raw(struct pt_image_section_cache *iscache,
		    struct pt_image *image, char *arg, const char *prog)
{
	uint64_t base;
	int isid, errcode, has_base;

	has_base = extract_base(arg, &base);
	if (has_base <= 0)
		return 1;

	isid = pt_iscache_add_file(iscache, arg, 0, UINT64_MAX, base);
	if (isid < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, arg, base, pt_errstr(pt_errcode(isid)));
		return 1;
	}

	errcode = pt_image_add_cached(image, iscache, isid, NULL);
	if (errcode < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, arg, base, pt_errstr(pt_errcode(errcode)));
		return 1;
	}

	return 0;
}

static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return XED_MACHINE_MODE_INVALID;

	case ptem_16bit:
		return XED_MACHINE_MODE_LEGACY_16;

	case ptem_32bit:
		return XED_MACHINE_MODE_LEGACY_32;

	case ptem_64bit:
		return XED_MACHINE_MODE_LONG_64;
	}

	return XED_MACHINE_MODE_INVALID;
}

static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip,
			   const struct ptxed_options *options)
{
	xed_print_info_t pi;
	char buffer[256];
	xed_bool_t ok;

	if (!inst || !options) {
		printf(" [internal error]");
		return;
	}

	if (options->print_raw_insn) {
		xed_uint_t length, i;

		length = xed_decoded_inst_get_length(inst);
		for (i = 0; i < length; ++i)
			printf(" %02x", xed_decoded_inst_get_byte(inst, i));

		for (; i < pt_max_insn_size; ++i)
			printf("   ");
	}

	xed_init_print_info(&pi);
	pi.p = inst;
	pi.buf = buffer;
	pi.blen = sizeof(buffer);
	pi.runtime_address = ip;

	if (options->att_format)
		pi.syntax = XED_SYNTAX_ATT;

	ok = xed_format_generic(&pi);
	if (!ok) {
		printf(" [xed print error]");
		return;
	}

	printf("  %s", buffer);
}

static void print_insn(const struct pt_insn *insn, xed_state_t *xed,
		       const struct ptxed_options *options, uint64_t offset)
{
	if (!insn || !options) {
		printf("[internal error]\n");
		return;
	}

	if (insn->resynced)
		printf("[overflow]\n");

	if (insn->enabled)
		printf("[enabled]\n");

	if (insn->resumed)
		printf("[resumed]\n");

	if (insn->speculative)
		printf("? ");

	if (options->print_offset)
		printf("%016" PRIx64 "  ", offset);

	printf("%016" PRIx64, insn->ip);

	if (!options->dont_print_insn) {
		xed_machine_mode_enum_t mode;
		xed_decoded_inst_t inst;
		xed_error_enum_t errcode;

		mode = translate_mode(insn->mode);

		xed_state_set_machine_mode(xed, mode);
		xed_decoded_inst_zero_set_mode(&inst, xed);

		errcode = xed_decode(&inst, insn->raw, insn->size);
		switch (errcode) {
		case XED_ERROR_NONE:
			xed_print_insn(&inst, insn->ip, options);
			break;

		default:
			printf(" [xed decode error: (%u) %s]", errcode,
			       xed_error_enum_t2str(errcode));
			break;
		}
	}

	printf("\n");

	if (insn->interrupted)
		printf("[interrupt]\n");

	if (insn->aborted)
		printf("[aborted]\n");

	if (insn->committed)
		printf("[committed]\n");

	if (insn->disabled)
		printf("[disabled]\n");

	if (insn->stopped)
		printf("[stopped]\n");
}

static void diagnose_insn(const char *errtype, struct pt_insn_decoder *decoder,
			  struct pt_insn *insn, int errcode)
{
	int err;
	uint64_t pos;

	err = pt_insn_get_offset(decoder, &pos);
	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		printf("[?, %" PRIx64 ": %s: %s]\n", insn->ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       insn->ip, errtype, pt_errstr(pt_errcode(errcode)));
}

static void decode_insn(struct pt_insn_decoder *decoder,
			const struct ptxed_options *options,
			struct ptxed_stats *stats)
{
	xed_state_t xed;
	uint64_t offset, sync;

	if (!options) {
		printf("[internal error]\n");
		return;
	}

	xed_state_zero(&xed);

	offset = 0ull;
	sync = 0ull;
	for (;;) {
		struct pt_insn insn;
		int errcode;

		/* Initialize the IP - we use it for error reporting. */
		insn.ip = 0ull;

		errcode = pt_insn_sync_forward(decoder);
		if (errcode < 0) {
			uint64_t new_sync;

			if (errcode == -pte_eos)
				break;

			diagnose_insn("sync error", decoder, &insn, errcode);

			/* Let's see if we made any progress.  If we haven't,
			 * we likely never will.  Bail out.
			 *
			 * We intentionally report the error twice to indicate
			 * that we tried to re-sync.  Maybe it even changed.
			 */
			errcode = pt_insn_get_offset(decoder, &new_sync);
			if (errcode < 0 || (new_sync <= sync))
				break;

			sync = new_sync;
			continue;
		}

		for (;;) {
			if (options->print_offset) {
				errcode = pt_insn_get_offset(decoder, &offset);
				if (errcode < 0)
					break;
			}

			errcode = pt_insn_next(decoder, &insn, sizeof(insn));
			if (errcode < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding the current instruction.
				 */
				if (insn.iclass != ptic_error) {
					if (!options->quiet)
						print_insn(&insn, &xed, options,
							   offset);
					if (stats)
						stats->insn += 1;
				}
				break;
			}

			if (!options->quiet)
				print_insn(&insn, &xed, options, offset);

			if (stats)
				stats->insn += 1;

			if (errcode & pts_eos) {
				if (!insn.disabled && !options->quiet)
					printf("[end of trace]\n");

				errcode = -pte_eos;
				break;
			}
		}

		/* We shouldn't break out of the loop without an error. */
		if (!errcode)
			errcode = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (errcode == -pte_eos)
			break;

		diagnose_insn("error", decoder, &insn, errcode);
	}
}

static void diagnose_block_at(const char *errtype, uint64_t pos,
			      struct pt_block *block, int errcode)
{
	if (!block) {
		printf("ptxed: internal error");
		return;
	}

	if (block->ninsn)
		printf("[%" PRIx64 ", %" PRIx64 "(+%x): %s: %s]\n", pos,
		       block->ip, block->ninsn, errtype,
		       pt_errstr(pt_errcode(errcode)));
	else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       block->ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
}

static void diagnose_block(const char *errtype,
			   struct pt_block_decoder *decoder,
			   struct pt_block *block, int errcode)
{
	int err;
	uint64_t pos;

	if (!block) {
		printf("ptxed: internal error");
		return;
	}

	err = pt_blk_get_offset(decoder, &pos);
	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		if (block->ninsn)
			printf("[?, %" PRIx64 "(+%x): %s: %s]\n", block->ip,
			       block->ninsn, errtype,
			       pt_errstr(pt_errcode(errcode)));
		else
			printf("[?, %" PRIx64 ": %s: %s]\n", block->ip, errtype,
			       pt_errstr(pt_errcode(errcode)));
	} else
		diagnose_block_at(errtype, pos, block, errcode);
}

static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip)
{
	xed_uint_t length, disp_width;

	if (!pip || !inst)
		return -pte_internal;

	length = xed_decoded_inst_get_length(inst);
	if (!length) {
		printf("[xed error: failed to determine instruction length]\n");
		return -pte_bad_insn;
	}

	ip += length;

	/* If it got a branch displacement it must be a branch.
	 *
	 * This includes conditional branches for which we don't know whether
	 * they were taken.  The next IP won't be used in this case as a
	 * conditional branch ends a block.  The next block will start with the
	 * correct IP.
	 */
	disp_width = xed_decoded_inst_get_branch_displacement_width(inst);
	if (disp_width)
		ip += xed_decoded_inst_get_branch_displacement(inst);

	*pip = ip;
	return 0;
}

static void print_block(struct pt_block *block,
			struct pt_image_section_cache *iscache,
			const struct ptxed_options *options, uint64_t offset)
{
	xed_machine_mode_enum_t mode;
	xed_state_t xed;
	uint64_t last_ip;

	if (!block || !options) {
		printf("[internal error]\n");
		return;
	}

	if (block->resynced)
		printf("[overflow]\n");

	if (block->enabled)
		printf("[enabled]\n");

	if (block->resumed)
		printf("[resumed]\n");

	mode = translate_mode(block->mode);
	xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);

	last_ip = 0ull;
	for (; block->ninsn; --block->ninsn) {
		xed_decoded_inst_t inst;
		xed_error_enum_t xederrcode;
		uint8_t raw[pt_max_insn_size], *praw;
		int size, errcode;

		/* For truncated block, the last instruction is provided in the
		 * block since it can't be read entirely from the image section
		 * cache.
		 */
		if (block->truncated && (block->ninsn == 1)) {
			praw = block->raw;
			size = block->size;
		} else {
			praw = raw;
			size = pt_iscache_read(iscache, raw, sizeof(raw),
					       block->isid, block->ip);
			if (size < 0) {
				printf(" [error reading insn: (%d) %s]\n", size,
				       pt_errstr(pt_errcode(size)));
				break;
			}
		}

		xed_decoded_inst_zero_set_mode(&inst, &xed);

		if (block->speculative)
			printf("? ");

		if (options->print_offset)
			printf("%016" PRIx64 "  ", offset);

		printf("%016" PRIx64, block->ip);

		xederrcode = xed_decode(&inst, praw, size);
		if (xederrcode != XED_ERROR_NONE) {
			printf(" [xed decode error: (%u) %s]\n", xederrcode,
			       xed_error_enum_t2str(xederrcode));
			break;
		}

		if (!options->dont_print_insn)
			xed_print_insn(&inst, block->ip, options);

		printf("\n");

		last_ip = block->ip;

		errcode = xed_next_ip(&block->ip, &inst, last_ip);
		if (errcode < 0) {
			diagnose_block_at("reconstruct error", offset, block,
					  errcode);
			break;
		}
	}

	/* Decode should have brought us to @block->end_ip. */
	if (last_ip != block->end_ip)
		diagnose_block_at("reconstruct error", offset, block,
				  -pte_nosync);

	if (block->interrupted)
		printf("[interrupt]\n");

	if (block->aborted)
		printf("[aborted]\n");

	if (block->committed)
		printf("[committed]\n");

	if (block->disabled)
		printf("[disabled]\n");

	if (block->stopped)
		printf("[stopped]\n");
}

static void decode_block(struct pt_block_decoder *decoder,
			 struct pt_image_section_cache *iscache,
			 const struct ptxed_options *options,
			 struct ptxed_stats *stats)
{
	uint64_t offset, sync;

	if (!options) {
		printf("[internal error]\n");
		return;
	}

	offset = 0ull;
	sync = 0ull;
	for (;;) {
		struct pt_block block;
		int errcode;

		/* Initialize IP and ninsn - we use it for error reporting. */
		block.ip = 0ull;
		block.ninsn = 0u;

		errcode = pt_blk_sync_forward(decoder);
		if (errcode < 0) {
			uint64_t new_sync;

			if (errcode == -pte_eos)
				break;

			diagnose_block("sync error", decoder, &block, errcode);

			/* Let's see if we made any progress.  If we haven't,
			 * we likely never will.  Bail out.
			 *
			 * We intentionally report the error twice to indicate
			 * that we tried to re-sync.  Maybe it even changed.
			 */
			errcode = pt_blk_get_offset(decoder, &new_sync);
			if (errcode < 0 || (new_sync <= sync))
				break;

			sync = new_sync;
			continue;
		}

		for (;;) {
			if (options->print_offset) {
				errcode = pt_blk_get_offset(decoder, &offset);
				if (errcode < 0)
					break;
			}

			errcode = pt_blk_next(decoder, &block, sizeof(block));
			if (errcode < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding some instructions.
				 */
				if (block.ninsn) {
					if (stats)
						stats->insn += block.ninsn;

					if (!options->quiet)
						print_block(&block, iscache,
							    options, offset);
				}
				break;
			}

			if (stats)
				stats->insn += block.ninsn;

			if (!options->quiet)
				print_block(&block, iscache, options, offset);

			if (errcode & pts_eos) {
				if (!block.disabled && !options->quiet)
					printf("[end of trace]\n");

				errcode = -pte_eos;
				break;
			}
		}

		/* We shouldn't break out of the loop without an error. */
		if (!errcode)
			errcode = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (errcode == -pte_eos)
			break;

		diagnose_block("error", decoder, &block, errcode);
	}
}

static void decode(struct ptxed_decoder *decoder,
		   struct pt_image_section_cache *iscache,
		   const struct ptxed_options *options,
		   struct ptxed_stats *stats)
{
	if (!decoder) {
		printf("[internal error]\n");
		return;
	}

	switch (decoder->type) {
	case pdt_insn_decoder:
		decode_insn(decoder->variant.insn, options, stats);
		break;

	case pdt_block_decoder:
		decode_block(decoder->variant.block, iscache, options, stats);
		break;
	}
}

static void print_stats(struct ptxed_stats *stats)
{
	if (!stats) {
		printf("[internal error]\n");
		return;
	}

	printf("insn: %" PRIu64 ".\n", stats->insn);
}

static int get_arg_uint64(uint64_t *value, const char *option, const char *arg,
			  const char *prog)
{
	char *rest;

	if (!value || !option || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
		return 0;
	}

	if (!arg || (arg[0] == '-' && arg[1] == '-')) {
		fprintf(stderr, "%s: %s: missing argument.\n", prog, option);
		return 0;
	}

	errno = 0;
	*value = strtoull(arg, &rest, 0);
	if (errno || *rest) {
		fprintf(stderr, "%s: %s: bad argument: %s.\n", prog, option,
			arg);
		return 0;
	}

	return 1;
}

static int get_arg_uint32(uint32_t *value, const char *option, const char *arg,
			  const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT32_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint32_t) val;

	return 1;
}

static int get_arg_uint8(uint8_t *value, const char *option, const char *arg,
			 const char *prog)
{
	uint64_t val;

	if (!get_arg_uint64(&val, option, arg, prog))
		return 0;

	if (val > UINT8_MAX) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	*value = (uint8_t) val;

	return 1;
}

extern int main(int argc, char *argv[])
{
	struct pt_image_section_cache *iscache;
	struct ptxed_decoder decoder;
	struct ptxed_options options;
	struct ptxed_stats stats;
	struct pt_config config;
	struct pt_image *image;
	const char *prog;
	int errcode, i;

	if (!argc) {
		help("");
		return 1;
	}

	prog = argv[0];
	iscache = NULL;
	image = NULL;

	memset(&decoder, 0, sizeof(decoder));
	decoder.type = pdt_block_decoder;

	memset(&options, 0, sizeof(options));
	memset(&stats, 0, sizeof(stats));

	pt_config_init(&config);

	iscache = pt_iscache_alloc(NULL);
	if (!iscache) {
		fprintf(stderr,
			"%s: failed to allocate image section cache.\n", prog);
		goto err;
	}

	image = pt_image_alloc(NULL);
	if (!image) {
		fprintf(stderr, "%s: failed to allocate image.\n", prog);
		goto err;
	}

	for (i = 1; i < argc;) {
		char *arg;

		arg = argv[i++];

		if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
			help(prog);
			goto out;
		}
		if (strcmp(arg, "--version") == 0) {
			version(prog);
			goto out;
		}
		if (strcmp(arg, "--pt") == 0) {
			if (argc <= i) {
				fprintf(stderr,
					"%s: --pt: missing argument.\n", prog);
				goto out;
			}
			arg = argv[i++];

			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: duplicate pt sources: %s.\n",
					prog, arg);
				goto err;
			}

			errcode = pt_cpu_errata(&config.errata, &config.cpu);
			if (errcode < 0)
				goto err;

			errcode = load_pt(&config, arg, prog);
			if (errcode < 0)
				goto err;

			switch (decoder.type) {
			case pdt_insn_decoder:
				decoder.variant.insn =
					pt_insn_alloc_decoder(&config);
				if (!decoder.variant.insn) {
					fprintf(stderr, "%s: failed to create "
						"decoder.\n", prog);
					goto err;
				}

				errcode =
					pt_insn_set_image(decoder.variant.insn,
							  image);
				if (errcode < 0) {
					fprintf(stderr,
						"%s: failed to set image.\n",
						prog);
					goto err;
				}
				break;

			case pdt_block_decoder:
				decoder.variant.block =
					pt_blk_alloc_decoder(&config);
				if (!decoder.variant.block) {
					fprintf(stderr, "%s: failed to create "
						"decoder.\n", prog);
					goto err;
				}

				errcode =
					pt_blk_set_image(decoder.variant.block,
							 image);
				if (errcode < 0) {
					fprintf(stderr,
						"%s: failed to set image.\n",
						prog);
					goto err;
				}
				break;
			}

			continue;
		}
		if (strcmp(arg, "--raw") == 0) {
			if (argc <= i) {
				fprintf(stderr,
					"%s: --raw: missing argument.\n", prog);
				goto out;
			}
			arg = argv[i++];

			errcode = load_raw(iscache, image, arg, prog);
			if (errcode < 0)
				goto err;

			continue;
		}
#if defined(FEATURE_ELF)
		if (strcmp(arg, "--elf") == 0) {
			uint64_t base;

			if (argc <= i) {
				fprintf(stderr,
					"%s: --elf: missing argument.\n", prog);
				goto out;
			}
			arg = argv[i++];
			base = 0ull;
			errcode = extract_base(arg, &base);
			if (errcode < 0)
				goto err;

			errcode = load_elf(iscache, image, arg, base, prog,
					   options.track_image);
			if (errcode < 0)
				goto err;

			continue;
		}
#endif /* defined(FEATURE_ELF) */
		if (strcmp(arg, "--att") == 0) {
			options.att_format = 1;
			continue;
		}
		if (strcmp(arg, "--no-inst") == 0) {
			options.dont_print_insn = 1;
			continue;
		}
		if (strcmp(arg, "--quiet") == 0 || strcmp(arg, "-q") == 0) {
			options.quiet = 1;
			continue;
		}
		if (strcmp(arg, "--offset") == 0) {
			options.print_offset = 1;
			continue;
		}
		if (strcmp(arg, "--raw-insn") == 0) {
			options.print_raw_insn = 1;
			continue;
		}
		if (strcmp(arg, "--stat") == 0) {
			options.print_stats = 1;
			continue;
		}
		if (strcmp(arg, "--cpu") == 0) {
			/* override cpu information before the decoder
			 * is initialized.
			 */
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify cpu before the pt source file.\n",
					prog);
				goto err;
			}
			if (argc <= i) {
				fprintf(stderr,
					"%s: --cpu: missing argument.\n", prog);
				goto out;
			}
			arg = argv[i++];

			if (strcmp(arg, "auto") == 0) {
				errcode = pt_cpu_read(&config.cpu);
				if (errcode < 0) {
					fprintf(stderr,
						"%s: error reading cpu: %s.\n",
						prog,
						pt_errstr(pt_errcode(errcode)));
					return 1;
				}
				continue;
			}

			if (strcmp(arg, "none") == 0) {
				memset(&config.cpu, 0, sizeof(config.cpu));
				continue;
			}

			errcode = pt_cpu_parse(&config.cpu, arg);
			if (errcode < 0) {
				fprintf(stderr,
					"%s: cpu must be specified as f/m[/s]\n",
					prog);
				goto err;
			}
			continue;
		}
		if (strcmp(arg, "--mtc-freq") == 0) {
			if (!get_arg_uint8(&config.mtc_freq, "--mtc-freq",
					   argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--nom-freq") == 0) {
			if (!get_arg_uint8(&config.nom_freq, "--nom-freq",
					   argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--cpuid-0x15.eax") == 0) {
			if (!get_arg_uint32(&config.cpuid_0x15_eax,
					    "--cpuid-0x15.eax", argv[i++],
					    prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--cpuid-0x15.ebx") == 0) {
			if (!get_arg_uint32(&config.cpuid_0x15_ebx,
					    "--cpuid-0x15.ebx", argv[i++],
					    prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0) {
			options.track_image = 1;
			continue;
		}

		if (strcmp(arg, "--insn-decoder") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before the pt "
					"source file.\n", arg, prog);
				goto err;
			}

			decoder.type = pdt_insn_decoder;
			continue;
		}

		if (strcmp(arg, "--block-decoder") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before the pt "
					"source file.\n", arg, prog);
				goto err;
			}

			decoder.type = pdt_block_decoder;
			continue;
		}

		fprintf(stderr, "%s: unknown option: %s.\n", prog, arg);
		goto err;
	}

	if (!ptxed_have_decoder(&decoder)) {
		fprintf(stderr, "%s: no pt file.\n", prog);
		goto err;
	}

	xed_tables_init();

	decode(&decoder, iscache, &options, &stats);

	if (options.print_stats)
		print_stats(&stats);

out:
	ptxed_free_decoder(&decoder);
	pt_image_free(image);
	pt_iscache_free(iscache);
	return 0;

err:
	ptxed_free_decoder(&decoder);
	pt_image_free(image);
	pt_iscache_free(iscache);
	return 1;
}
