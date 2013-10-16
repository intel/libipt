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

#include "pt_decode.h"
#include "pt_config.h"
#include "pt_version.h"

#include "load.h"
#include "disas.h"
#include "decode.h"
#include "memory.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


struct option {
	/* The long option name. */
	const char *name;

	/* A short abbreviation of the option name. */
	const char *abbrv;

	/* The function to process the option. */
	int (*process)(const char **);

	/* The argument count for this option. */
	int argc;

	/* A string enumerating the option's arguments. */
	const char *args;

	/* The raw arguments of the option. */
	const char **argv;
};

/* The name of the program. */
static const char *opt_prog = "ptdump";

/* The loaded executable file. */
static struct load_map *opt_loadmap;

/* The pt decoder. */
static struct pt_decoder *opt_decoder;

/* The disassembler's initial proceed flags. */
int opt_pflags;


static int help(const char **);

static int version(const char **argv)
{
	struct pt_version v = pt_library_version();

	printf("%s-%u.%u.%u%s / libipt-%u.%u.%u%s\n", opt_prog,
	       PT_VERSION_MAJOR, PT_VERSION_MINOR, PT_VERSION_BUILD,
	       PT_VERSION_EXT, v.major, v.minor, v.build, v.ext);
	exit(0);
}

static int flags_noret(const char **argv)
{
	opt_pflags &= ~pf_ptev_compression;

	return 0;
}

static int flags_no_inst(const char **argv)
{
	opt_pflags |= pf_no_inst;

	return 0;
}

static int opt_load_pt(const char **argv)
{
	struct pt_config config;
	uint8_t *pt;
	size_t size;
	int errcode;

	if (opt_decoder) {
		fprintf(stderr, "%s: duplicate pt sources.\n", opt_prog);
		return -1;
	}

	pt = map_file(argv[0], &size);
	if (!pt)
		return -1;

	memset(&config, 0, sizeof(config));

	/* Assume that we're decoding on the system on which we recorded. */
	errcode = pt_configure(&config);
	if (errcode < 0) {
		fprintf(stderr, "%s: failed to configure pt decoder.\n",
			opt_prog);
		return -1;
	}

	config.begin = pt;
	config.end = pt + size;

	opt_decoder = pt_alloc_decoder(&config);
	if (!opt_decoder) {
		fprintf(stderr, "%s: failed to allcoate pt decoder.\n",
			opt_prog);
		return -1;
	}

	/* We will leak the mapped memory. */

	return 0;
}

#if defined(FEATURE_ELF)

static int opt_load_elf(const char **argv)
{
	uint64_t base;
	char *sep, *rest;

	base = 0;
	sep = strstr(argv[0], ":");
	if (sep) {
		errno = 0;
		base = strtoull(sep+1, &rest, 0);
		if (errno || *rest) {
			fprintf(stderr, "%s: bad base argument: %s.\n",
				opt_prog, sep+1);
			return -1;
		}

		*sep = 0;
	}

	return load_elf(argv[0], &opt_loadmap, base);
}

#endif /* defined(FEATURE_ELF) */

static int opt_load_raw(const char **argv)
{
	uint64_t base;
	char *rest;

	errno = 0;
	base = strtoull(argv[1], &rest, 0);
	if (errno || *rest) {
		fprintf(stderr, "%s: bad base argument: %s.\n",
			opt_prog, argv[1]);
		return -1;
	}

	return load_raw(argv[0], &opt_loadmap, base);
}

struct option opts[] = {
	{
		/* .name = */ "--help",
		/* .abbrv = */ "-h",
		/* .process = */ help,
		/* .argc = */ 0,
		/* .args = */ NULL,
		/* .argv = */ NULL
	},
	{
		/* .name = */ "--version",
		/* .abbrv = */ NULL,
		/* .process = */ version,
		/* .argc = */ 0,
		/* .args = */ NULL,
		/* .argv = */ NULL
	},
	{
		/* .name = */ "--no-zret",
		/* .abbrv = */ NULL,
		/* .process = */ flags_noret,
		/* .argc = */ 0,
		/* .args = */ NULL,
		/* .argv = */ NULL
	},
	{
		/* .name = */ "--no-inst",
		/* .abbrv = */ NULL,
		/* .process = */ flags_no_inst,
		/* .argc = */ 0,
		/* .args = */ NULL,
		/* .argv = */ NULL
	},
	{
		/* .name = */ "--pt",
		/* .abbrv = */ NULL,
		/* .process = */ opt_load_pt,
		/* .argc = */ 1,
		/* .args = */ "<file>",
		/* .argv = */ NULL
	},
#if defined(FEATURE_ELF)
	{
		/* .name = */ "--elf",
		/* .abbrv = */ NULL,
		/* .process = */ opt_load_elf,
		/* .argc = */ 1,
		/* .args = */ "<file>[:<base>]",
		/* .argv = */ NULL
	},
#endif /* defined(FEATURE_ELF) */
	{
		/* .name = */ "--raw",
		/* .abbrv = */ NULL,
		/* .process = */ opt_load_raw,
		/* .argc = */ 2,
		/* .args = */ "<file> <base>",
		/* .argv = */ NULL
	}
};

#define num_opts (sizeof(opts) / sizeof(struct option))

static int help(const char **argv)
{
	printf("usage: %s [<options>]\n\n"
	       "options:\n"
	       "  --help|-h                this text.\n"
	       "  --version                display version information and exit.\n"
	       "  --no-zret                assume no return compression.\n"
	       "  --no-inst                do not print instructions (only addresses).\n"
	       "  --pt <file>              load the processor trace data from <file>.\n"
#if defined(FEATURE_ELF)
	       "  --elf <<file>[:<base>]   load an ELF from <file> at address <base>.\n"
	       "                           use the default load address if <base> is omitted.\n"
#endif /* defined(FEATURE_ELF) */
	       "  --raw <file> <base>      load a raw binary from <file> at address <base>.\n"
	       "\n"
#if defined(FEATURE_ELF)
	       "You must specify at least one binary or ELF file (--raw|--elf).\n"
#else /* defined(FEATURE_ELF) */
	       "You must specify at least one binary file (--raw).\n"
#endif /* defined(FEATURE_ELF) */
	       "You must specify exactly one processor trace file (--pt).\n",
	       opt_prog);

	exit(0);
}

static int opt_arg_error(struct option *opt)
{
	fprintf(stderr, "%s: %s: insufficient arguments, expected: %d.\n",
		opt_prog, opt->name, opt->argc);
	return -1;
}

static int unknown_option(const char *name)
{
	fprintf(stderr, "%s: %s: unknown option. Use --help or -h for help.\n",
		opt_prog, name);
	return -1;
}

static int process_options(int argc, const char **argv)
{
	size_t a, o;

	a = 1;
	while (argv[a]) {
		const char *name = argv[a++];

		for (o = 0; o < num_opts; ++o) {
			struct option *opt = &opts[o];

			if ((opt->name && (strcmp(name, opt->name) == 0)) ||
			    (opt->abbrv && (strcmp(name, opt->abbrv) == 0))) {
				int s, errcode;

				opt->argv = &argv[a];

				for (s = 0; s < opt->argc; ++s)
					if (!argv[a++])
						return opt_arg_error(opt);

				errcode = opt->process(opt->argv);
				if (errcode < 0)
					return errcode;

				break;
			}

		}

		if (o == num_opts)
			return unknown_option(name);
	}

	if (!opt_decoder) {
		fprintf(stderr,
			"%s: no processor trace file specified.\n", opt_prog);
		return -1;
	}

	if (!opt_loadmap) {
		fprintf(stderr,
			"%s: no image file specified specified.\n", opt_prog);
		return -1;
	}

	return 0;
}

extern int main(int argc, const char **argv)
{
	int errcode;

	/* help exits with exit status 0, no need to return. */
	if (!argc)
		help(NULL);

	opt_prog = argv[0];
	opt_pflags = pf_ptev_compression;

	errcode = process_options(argc, argv);
	if (errcode < 0)
		return errcode;

	disas(opt_decoder, opt_loadmap);

	unload(opt_loadmap);

	return 0;
}
