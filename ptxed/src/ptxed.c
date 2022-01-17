/*
 * Copyright (c) 2013-2022, Intel Corporation
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

	/* Track blocks in the output.
	 *
	 * This only applies to the block decoder.
	 */
	uint32_t track_blocks:1;

	/* Print in AT&T format. */
	uint32_t att_format:1;

	/* Print the offset into the trace file. */
	uint32_t print_offset:1;

	/* Print the current timestamp. */
	uint32_t print_time:1;

	/* Print the raw bytes for an insn. */
	uint32_t print_raw_insn:1;

	/* Perform checks. */
	uint32_t check:1;
};

/* A collection of flags selecting which stats to collect/print. */
enum ptxed_stats_flag {
	/* Collect number of instructions. */
	ptxed_stat_insn		= (1 << 0),

	/* Collect number of blocks. */
	ptxed_stat_blocks	= (1 << 1)
};

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;

	/* The number of blocks.
	 *
	 * This only applies to the block decoder.
	 */
	uint64_t blocks;

	/* A collection of flags saying which statistics to collect/print. */
	uint32_t flags;
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
	printf("usage: %s [<options>]\n\n", name);
	printf("options:\n");
	printf("  --help|-h                            this text.\n");
	printf("  --version                            display version information and exit.\n");
	printf("  --att                                print instructions in att format.\n");
	printf("  --no-inst                            do not print instructions (only addresses).\n");
	printf("  --quiet|-q                           do not print anything (except errors).\n");
	printf("  --offset                             print the offset into the trace file.\n");
	printf("  --time                               print the current timestamp.\n");
	printf("  --raw-insn                           print the raw bytes of each instruction.\n");
	printf("  --check                              perform checks (expensive).\n");
	printf("  --filter:addr<n>_cfg <cfg>           set IA32_RTIT_CTL.ADDRn_CFG to <cfg>.\n");
	printf("  --filter:addr<n>_a <base>            set IA32_RTIT_ADDRn_A to <base>.\n");
	printf("  --filter:addr<n>_b <limit>           set IA32_RTIT_ADDRn_B to <limit>.\n");
	printf("  --stat                               print statistics (even when quiet).\n");
	printf("                                       collects all statistics unless one or more are selected.\n");
	printf("  --stat:insn                          collect number of instructions.\n");
	printf("  --verbose|-v                         print various information (even when quiet).\n");
	printf("  --pt <file>[:<from>[-<to>]]          load the processor trace data from <file>.\n");
	printf("                                       an optional offset or range can be given.\n");
#if defined(FEATURE_ELF)
	printf("  --elf <<file>[:<base>]               load an ELF from <file> at address <base>.\n");
	printf("                                       use the default load address if <base> is omitted.\n");
#endif /* defined(FEATURE_ELF) */
	printf("  --raw <file>[:<from>[-<to>]]:<base>  load a raw binary from <file> at address <base>.\n");
	printf("                                       an optional offset or range can be given.\n");
	printf("  --cpu none|auto|f/m[/s]              set cpu to the given value and decode according to:\n");
	printf("                                         none     spec (default)\n");
	printf("                                         auto     current cpu\n");
	printf("                                         f/m[/s]  family/model[/stepping]\n");
	printf("  --mtc-freq <n>                       set the MTC frequency (IA32_RTIT_CTL[17:14]) to <n>.\n");
	printf("  --nom-freq <n>                       set the nominal frequency (MSR_PLATFORM_INFO[15:8]) to <n>.\n");
	printf("  --cpuid-0x15.eax                     set the value of cpuid[0x15].eax.\n");
	printf("  --cpuid-0x15.ebx                     set the value of cpuid[0x15].ebx.\n");
	printf("  --insn-decoder                       use the instruction flow decoder (default).\n");
	printf("  --block-decoder                      use the block decoder.\n");
	printf("  --block:show-blocks                  show blocks in the output.\n");
	printf("  --block:end-on-call                  set the end-on-call block decoder flag.\n");
	printf("\n");
#if defined(FEATURE_ELF)
	printf("You must specify at least one binary or ELF file (--raw|--elf).\n");
#else /* defined(FEATURE_ELF) */
	printf("You must specify at least one binary file (--raw).\n");
#endif /* defined(FEATURE_ELF) */
	printf("You must specify exactly one processor trace file (--pt).\n");
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

/* Preprocess a filename argument.
 *
 * A filename may optionally be followed by a file offset or a file range
 * argument separated by ':'.  Split the original argument into the filename
 * part and the offset/range part.
 *
 * If no end address is specified, set @size to zero.
 * If no offset is specified, set @offset to zero.
 *
 * Returns zero on success, a negative error code otherwise.
 */
static int preprocess_filename(char *filename, uint64_t *offset, uint64_t *size)
{
	uint64_t begin, end;
	char *range;
	int parts;

	if (!filename || !offset || !size)
		return -pte_internal;

	/* Search from the end as the filename may also contain ':'. */
	range = strrchr(filename, ':');
	if (!range) {
		*offset = 0ull;
		*size = 0ull;

		return 0;
	}

	/* Let's try to parse an optional range suffix.
	 *
	 * If we can, remove it from the filename argument.
	 * If we can not, assume that the ':' is part of the filename, e.g. a
	 * drive letter on Windows.
	 */
	parts = parse_range(range + 1, &begin, &end);
	if (parts <= 0) {
		*offset = 0ull;
		*size = 0ull;

		return 0;
	}

	if (parts == 1) {
		*offset = begin;
		*size = 0ull;

		*range = 0;

		return 0;
	}

	if (parts == 2) {
		if (end <= begin)
			return -pte_invalid;

		*offset = begin;
		*size = end - begin;

		*range = 0;

		return 0;
	}

	return -pte_internal;
}

static int load_file(uint8_t **buffer, size_t *psize, const char *filename,
		     uint64_t offset, uint64_t size, const char *prog)
{
	uint8_t *content;
	size_t read;
	FILE *file;
	long fsize, begin, end;
	int errcode;

	if (!buffer || !psize || !filename || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "");
		return -1;
	}

	errno = 0;
	file = fopen(filename, "rb");
	if (!file) {
		fprintf(stderr, "%s: failed to open %s: %d.\n",
			prog, filename, errno);
		return -1;
	}

	errcode = fseek(file, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, filename, errno);
		goto err_file;
	}

	fsize = ftell(file);
	if (fsize < 0) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog, filename, errno);
		goto err_file;
	}

	begin = (long) offset;
	if (((uint64_t) begin != offset) || (fsize <= begin)) {
		fprintf(stderr,
			"%s: bad offset 0x%" PRIx64 " into %s.\n",
			prog, offset, filename);
		goto err_file;
	}

	end = fsize;
	if (size) {
		uint64_t range_end;

		range_end = offset + size;
		if ((uint64_t) end < range_end) {
			fprintf(stderr,
				"%s: bad range 0x%" PRIx64 " in %s.\n",
				prog, range_end, filename);
			goto err_file;
		}

		end = (long) range_end;
	}

	fsize = end - begin;

	content = malloc(fsize);
	if (!content) {
		fprintf(stderr, "%s: failed to allocated memory %s.\n",
			prog, filename);
		goto err_file;
	}

	errcode = fseek(file, begin, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, filename, errno);
		goto err_content;
	}

	read = fread(content, fsize, 1, file);
	if (read != 1) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog, filename, errno);
		goto err_content;
	}

	fclose(file);

	*buffer = content;
	*psize = fsize;

	return 0;

err_content:
	free(content);

err_file:
	fclose(file);
	return -1;
}

static int load_pt(struct pt_config *config, char *arg, const char *prog)
{
	uint64_t foffset, fsize;
	uint8_t *buffer;
	size_t size;
	int errcode;

	errcode = preprocess_filename(arg, &foffset, &fsize);
	if (errcode < 0) {
		fprintf(stderr, "%s: bad file %s: %s.\n", prog, arg,
			pt_errstr(pt_errcode(errcode)));
		return -1;
	}

	errcode = load_file(&buffer, &size, arg, foffset, fsize, prog);
	if (errcode < 0)
		return errcode;

	config->begin = buffer;
	config->end = buffer + size;

	return 0;
}

static int load_raw(struct pt_image_section_cache *iscache,
		    struct pt_image *image, char *arg, const char *prog)
{
	uint64_t base, foffset, fsize;
	int isid, errcode, has_base;

	has_base = extract_base(arg, &base);
	if (has_base <= 0)
		return -1;

	errcode = preprocess_filename(arg, &foffset, &fsize);
	if (errcode < 0) {
		fprintf(stderr, "%s: bad file %s: %s.\n", prog, arg,
			pt_errstr(pt_errcode(errcode)));
		return -1;
	}

	if (!fsize)
		fsize = UINT64_MAX;

	isid = pt_iscache_add_file(iscache, arg, foffset, fsize, base);
	if (isid < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, arg, base, pt_errstr(pt_errcode(isid)));
		return -1;
	}

	errcode = pt_image_add_cached(image, iscache, isid, NULL);
	if (errcode < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, arg, base, pt_errstr(pt_errcode(errcode)));
		return -1;
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

static const char *visualize_iclass(enum pt_insn_class iclass)
{
	switch (iclass) {
	case ptic_error:
		return "unknown/error";

	case ptic_other:
		return "other";

	case ptic_call:
		return "near call";

	case ptic_return:
		return "near return";

	case ptic_jump:
		return "near jump";

	case ptic_cond_jump:
		return "cond jump";

	case ptic_far_call:
		return "far call";

	case ptic_far_return:
		return "far return";

	case ptic_far_jump:
		return "far jump";
	}

	return "undefined";
}

static void check_insn_iclass(const xed_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_category_enum_t category;
	xed_iclass_enum_t iclass;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	category = xed_inst_category(inst);
	iclass = xed_inst_iclass(inst);

	switch (insn->iclass) {
	case ptic_error:
		break;

	case ptic_other:
		switch (category) {
		default:
			return;

		case XED_CATEGORY_CALL:
		case XED_CATEGORY_RET:
		case XED_CATEGORY_COND_BR:
		case XED_CATEGORY_UNCOND_BR:
		case XED_CATEGORY_INTERRUPT:
		case XED_CATEGORY_SYSCALL:
		case XED_CATEGORY_SYSRET:
			break;
		}
		break;

	case ptic_call:
		if (iclass == XED_ICLASS_CALL_NEAR)
			return;

		break;

	case ptic_return:
		if (iclass == XED_ICLASS_RET_NEAR)
			return;

		break;

	case ptic_jump:
		if (iclass == XED_ICLASS_JMP)
			return;

		break;

	case ptic_cond_jump:
		if (category == XED_CATEGORY_COND_BR)
			return;

		break;

	case ptic_far_call:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_AMD:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_VMCALL:
			return;
		}
		break;

	case ptic_far_return:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_IRET:
		case XED_ICLASS_IRETD:
		case XED_ICLASS_IRETQ:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_VMLAUNCH:
		case XED_ICLASS_VMRESUME:
			return;
		}
		break;

	case ptic_far_jump:
		if (iclass == XED_ICLASS_JMP_FAR)
			return;

		break;
	}

	/* If we get here, @insn->iclass doesn't match XED's classification. */
	printf("[%" PRIx64 ", %" PRIx64 ": iclass error: iclass: %s, "
	       "xed iclass: %s, category: %s]\n", offset, insn->ip,
	       visualize_iclass(insn->iclass), xed_iclass_enum_t2str(iclass),
	       xed_category_enum_t2str(category));

}

static void check_insn_decode(xed_decoded_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_error_enum_t errcode;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	xed_decoded_inst_set_mode(inst, translate_mode(insn->mode),
				  XED_ADDRESS_WIDTH_INVALID);

	/* Decode the instruction (again).
	 *
	 * We may have decoded the instruction already for printing.  In this
	 * case, we will decode it twice.
	 *
	 * The more common use-case, however, is to check the instruction class
	 * while not printing instructions since the latter is too expensive for
	 * regular use with long traces.
	 */
	errcode = xed_decode(inst, insn->raw, insn->size);
	if (errcode != XED_ERROR_NONE) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: (%u) %s]\n",
		       offset, insn->ip, errcode,
		       xed_error_enum_t2str(errcode));
		return;
	}

	if (!xed_decoded_inst_valid(inst)) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: "
		       "invalid instruction]\n", offset, insn->ip);
		return;
	}
}

static void check_insn(const struct pt_insn *insn, uint64_t offset)
{
	xed_decoded_inst_t inst;

	xed_decoded_inst_zero(&inst);
	check_insn_decode(&inst, insn, offset);

	/* We need a valid instruction in order to do further checks.
	 *
	 * Invalid instructions have already been diagnosed.
	 */
	if (!xed_decoded_inst_valid(&inst))
		return;

	check_insn_iclass(xed_decoded_inst_inst(&inst), insn, offset);
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
		       const struct ptxed_options *options, uint64_t offset,
		       uint64_t time)
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

	if (options->print_time)
		printf("%016" PRIx64 "  ", time);

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
	uint64_t offset, sync, time;

	if (!options) {
		printf("[internal error]\n");
		return;
	}

	xed_state_zero(&xed);

	offset = 0ull;
	sync = 0ull;
	time = 0ull;
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
			if (options->print_offset || options->check) {
				errcode = pt_insn_get_offset(decoder, &offset);
				if (errcode < 0)
					break;
			}

			if (options->print_time) {
				errcode = pt_insn_time(decoder, &time, NULL,
						       NULL);
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
							   offset, time);
					if (stats)
						stats->insn += 1;

					if (options->check)
						check_insn(&insn, offset);
				}
				break;
			}

			if (!options->quiet)
				print_insn(&insn, &xed, options, offset, time);

			if (stats)
				stats->insn += 1;

			if (options->check)
				check_insn(&insn, offset);

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

static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache)
{
	if (!insn || !block)
		return -pte_internal;

	/* We can't read from an empty block. */
	if (!block->ninsn)
		return -pte_invalid;

	memset(insn, 0, sizeof(*insn));
	insn->mode = block->mode;
	insn->ip = ip;

	/* The last instruction in a block may be truncated. */
	if ((ip == block->end_ip) && block->truncated) {
		if (!block->size || (sizeof(insn->raw) < (size_t) block->size))
			return -pte_bad_insn;

		insn->size = block->size;
		memcpy(insn->raw, block->raw, insn->size);
	} else {
		int size;

		size = pt_iscache_read(iscache, insn->raw, sizeof(insn->raw),
				       block->isid, ip);
		if (size < 0)
			return size;

		insn->isid = block->isid;
		insn->size = (uint8_t) size;
	}

	return 0;
}

static void diagnose_block_at(const char *errtype, int errcode,
			      struct pt_block_decoder *decoder, uint64_t ip)
{
	uint64_t pos;
	int err;

	err = pt_blk_get_offset(decoder, &pos);
	if (err < 0) {
		printf("[could not determine offset: %s]\n",
		       pt_errstr(pt_errcode(err)));

		printf("[?, %" PRIx64 ": %s: %s]\n", ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos, ip,
		       errtype, pt_errstr(pt_errcode(errcode)));
}

static void diagnose_block(const char *errtype, int errcode,
			   const struct pt_block *block,
			   struct pt_block_decoder *decoder,
			   struct pt_image_section_cache *iscache)
{
	uint64_t ip;
	int err;

	if (!block) {
		printf("ptxed: internal error");
		return;
	}

	/* Determine the IP at which to report the error.
	 *
	 * Depending on the type of error, the IP varies between that of the
	 * last instruction in @block or the next instruction outside of @block.
	 *
	 * When the block is empty, we use the IP of the block itself,
	 * i.e. where the first instruction should have been.
	 */
	if (!block->ninsn)
		ip = block->ip;
	else {
		ip = block->end_ip;

		switch (errcode) {
		case -pte_nomap:
		case -pte_bad_insn: {
			struct pt_insn insn;
			xed_decoded_inst_t inst;
			xed_error_enum_t xederr;

			/* Decode failed when trying to fetch or decode the next
			 * instruction.  Since indirect or conditional branches
			 * end a block and don't cause an additional fetch, we
			 * should be able to reach that IP from the last
			 * instruction in @block.
			 *
			 * We ignore errors and fall back to the IP of the last
			 * instruction.
			 */
			err = block_fetch_insn(&insn, block, ip, iscache);
			if (err < 0)
				break;

			xed_decoded_inst_zero(&inst);
			xed_decoded_inst_set_mode(&inst,
						  translate_mode(insn.mode),
						  XED_ADDRESS_WIDTH_INVALID);

			xederr = xed_decode(&inst, insn.raw, insn.size);
			if (xederr != XED_ERROR_NONE)
				break;

			(void) xed_next_ip(&ip, &inst, insn.ip);
		}
			break;

		default:
			break;
		}
	}

	diagnose_block_at(errtype, errcode, decoder, ip);
}

static void print_block(const struct pt_block *block,
			struct pt_block_decoder *decoder,
			struct pt_image_section_cache *iscache,
			const struct ptxed_options *options,
			const struct ptxed_stats *stats,
			uint64_t offset, uint64_t time)
{
	xed_machine_mode_enum_t mode;
	xed_state_t xed;
	uint64_t ip;
	uint16_t ninsn;

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

	if (options->track_blocks) {
		printf("[block");
		if (stats)
			printf(" %" PRIx64, stats->blocks);
		printf("]\n");
	}

	mode = translate_mode(block->mode);
	xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);

	/* There's nothing to do for empty blocks. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	ip = block->ip;
	for (;;) {
		struct pt_insn insn;
		xed_decoded_inst_t inst;
		xed_error_enum_t xederrcode;
		int errcode;

		if (block->speculative)
			printf("? ");

		if (options->print_offset)
			printf("%016" PRIx64 "  ", offset);

		if (options->print_time)
			printf("%016" PRIx64 "  ", time);

		printf("%016" PRIx64, ip);

		errcode = block_fetch_insn(&insn, block, ip, iscache);
		if (errcode < 0) {
			printf(" [fetch error: %s]\n",
			       pt_errstr(pt_errcode(errcode)));
			break;
		}

		xed_decoded_inst_zero_set_mode(&inst, &xed);

		xederrcode = xed_decode(&inst, insn.raw, insn.size);
		if (xederrcode != XED_ERROR_NONE) {
			printf(" [xed decode error: (%u) %s]\n", xederrcode,
			       xed_error_enum_t2str(xederrcode));
			break;
		}

		if (!options->dont_print_insn)
			xed_print_insn(&inst, insn.ip, options);

		printf("\n");

		ninsn -= 1;
		if (!ninsn)
			break;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			diagnose_block_at("reconstruct error", errcode,
					  decoder, ip);
			break;
		}
	}

	/* Decode should have brought us to @block->end_ip. */
	if (ip != block->end_ip)
		diagnose_block_at("reconstruct error", -pte_nosync, decoder,
				  ip);

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

static void check_block(const struct pt_block *block,
			struct pt_image_section_cache *iscache,
			uint64_t offset)
{
	struct pt_insn insn;
	xed_decoded_inst_t inst;
	uint64_t ip;
	uint16_t ninsn;
	int errcode;

	if (!block) {
		printf("[internal error]\n");
		return;
	}

	/* There's nothing to check for an empty block. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	ip = block->ip;
	do {
		errcode = block_fetch_insn(&insn, block, ip, iscache);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": fetch error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}

		xed_decoded_inst_zero(&inst);
		check_insn_decode(&inst, &insn, offset);

		/* We need a valid instruction in order to do further checks.
		 *
		 * Invalid instructions have already been diagnosed.
		 */
		if (!xed_decoded_inst_valid(&inst))
			return;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}
	} while (--ninsn);

	/* We reached the end of the block.  Both @insn and @inst refer to the
	 * last instruction in @block.
	 *
	 * Check that we reached the end IP of the block.
	 */
	if (insn.ip != block->end_ip) {
		printf("[%" PRIx64 ", %" PRIx64 ": error: did not reach end: %"
		       PRIx64 "]\n", offset, insn.ip, block->end_ip);
	}

	/* Check the last instruction's classification, if available. */
	insn.iclass = block->iclass;
	if (insn.iclass)
		check_insn_iclass(xed_decoded_inst_inst(&inst), &insn, offset);
}

static void decode_block(struct pt_block_decoder *decoder,
			 struct pt_image_section_cache *iscache,
			 const struct ptxed_options *options,
			 struct ptxed_stats *stats)
{
	uint64_t offset, sync, time;

	if (!options) {
		printf("[internal error]\n");
		return;
	}

	offset = 0ull;
	sync = 0ull;
	time = 0ull;
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

			diagnose_block("sync error", errcode, &block, decoder,
				       iscache);

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
			if (options->print_offset || options->check) {
				errcode = pt_blk_get_offset(decoder, &offset);
				if (errcode < 0)
					break;
			}

			if (options->print_time) {
				errcode = pt_blk_time(decoder, &time, NULL,
						      NULL);
				if (errcode < 0)
					break;
			}

			errcode = pt_blk_next(decoder, &block, sizeof(block));
			if (errcode < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding some instructions.
				 */
				if (block.ninsn) {
					if (stats) {
						stats->insn += block.ninsn;
						stats->blocks += 1;
					}

					if (!options->quiet)
						print_block(&block, decoder,
							    iscache, options,
							    stats, offset,
							    time);

					if (options->check)
						check_block(&block, iscache,
							    offset);
				}
				break;
			}

			if (stats) {
				stats->insn += block.ninsn;
				stats->blocks += 1;
			}

			if (!options->quiet)
				print_block(&block, decoder, iscache, options,
					    stats, offset, time);

			if (options->check)
				check_block(&block, iscache, offset);

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

		diagnose_block("error", errcode, &block, decoder, iscache);
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

	if (stats->flags & ptxed_stat_insn)
		printf("insn: %" PRIu64 ".\n", stats->insn);

	if (stats->flags & ptxed_stat_blocks)
		printf("blocks:\t%" PRIu64 ".\n", stats->blocks);
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

static int ptxed_addr_cfg(struct pt_config *config, uint8_t filter,
			  const char *option, const char *arg, const char *prog)
{
	uint64_t addr_cfg;

	if (!config || !option || !arg || !prog) {
		fprintf(stderr, "%s: internal error.\n", prog ? prog : "?");
		return 0;
	}

	if (!get_arg_uint64(&addr_cfg, option, arg, prog))
		return 0;

	if (15 < addr_cfg) {
		fprintf(stderr, "%s: %s: value too big: %s.\n", prog, option,
			arg);
		return 0;
	}

	/* Make sure the shift doesn't overflow. */
	if (15 < filter) {
		fprintf(stderr, "%s: internal error.\n", prog);
		return 0;
	}

	addr_cfg <<= (filter * 4);

	config->addr_filter.config.addr_cfg |= addr_cfg;

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
		if (strcmp(arg, "--time") == 0) {
			options.print_time = 1;
			continue;
		}
		if (strcmp(arg, "--raw-insn") == 0) {
			options.print_raw_insn = 1;
			continue;
		}
		if (strcmp(arg, "--filter:addr0_cfg") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!ptxed_addr_cfg(&config, 0, arg, argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr0_a") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr0_a, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr0_b") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr0_b, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr1_cfg") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!ptxed_addr_cfg(&config, 1, arg, argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr1_a") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr1_a, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr1_b") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr1_b, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr2_cfg") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!ptxed_addr_cfg(&config, 2, arg, argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr2_a") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr2_a, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr2_b") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr2_b, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr3_cfg") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!ptxed_addr_cfg(&config, 3, arg, argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr3_a") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr3_a, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--filter:addr3_b") == 0) {
			if (ptxed_have_decoder(&decoder)) {
				fprintf(stderr,
					"%s: please specify %s before --pt.\n",
					prog, arg);
				goto err;
			}

			if (!get_arg_uint64(&config.addr_filter.addr3_b, arg,
					    argv[i++], prog))
				goto err;

			continue;
		}
		if (strcmp(arg, "--check") == 0) {
			options.check = 1;
			continue;
		}
		if (strcmp(arg, "--stat") == 0) {
			options.print_stats = 1;
			continue;
		}
		if (strcmp(arg, "--stat:insn") == 0) {
			stats.flags |= ptxed_stat_insn;
			continue;
		}
		if (strcmp(arg, "--stat:blocks") == 0) {
			stats.flags |= ptxed_stat_blocks;
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

		if (strcmp(arg, "--block:show-blocks") == 0) {
			options.track_blocks = 1;
			continue;
		}

		if (strcmp(arg, "--block:end-on-call") == 0) {
			config.flags.variant.block.end_on_call = 1;
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

	/* If we didn't select any statistics, select them all depending on the
	 * decoder type.
	 */
	if (options.print_stats && !stats.flags) {
		stats.flags |= ptxed_stat_insn;

		if (decoder.type == pdt_block_decoder)
			stats.flags |= ptxed_stat_blocks;
	}

	decode(&decoder, iscache, &options,
	       options.print_stats ? &stats : NULL);

	if (options.print_stats)
		print_stats(&stats);

out:
	ptxed_free_decoder(&decoder);
	pt_image_free(image);
	pt_iscache_free(iscache);
	free(config.begin);
	return 0;

err:
	ptxed_free_decoder(&decoder);
	pt_image_free(image);
	pt_iscache_free(iscache);
	free(config.begin);
	return 1;
}
