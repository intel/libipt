/*
 * Copyright (c) 2013-2015, Intel Corporation
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

#include "errcode.h"
#include "parse.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *pt_suffix = ".pt";
const char *exp_suffix = ".exp";

enum {
	pd_len = 1024
};

/* Deallocates the memory used by @p, closes all files, clears and
 * zeroes the fields.
 */
static void p_free(struct parser *p)
{
	if (!p)
		return;

	yasm_free(p->y);
	pd_free(p->pd);
	free(p->ptfilename);

	free(p);
}

/* Initializes @p with @pttfile and @conf.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 * Returns -err_internal if @p is the NULL pointer.
 */
static struct parser *p_alloc(const char *pttfile, const struct pt_config *conf)
{
	size_t n;
	struct parser *p;

	if (!conf)
		return NULL;

	if (!pttfile)
		return NULL;

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;

	p->y = yasm_alloc(pttfile);
	if (!p->y)
		goto error;

	n = strlen(p->y->fileroot) + 1;

	p->ptfilename = malloc(n+strlen(pt_suffix));
	if (!p->ptfilename)
		goto error;

	strcpy(p->ptfilename, p->y->fileroot);
	strcat(p->ptfilename, pt_suffix);

	p->pd = pd_alloc(pd_len);
	if (!p->pd)
		goto error;

	p->pt_labels = l_alloc();
	if (!p->pt_labels)
		goto error;

	p->conf = conf;

	return p;

error:
	p_free(p);
	return NULL;
}

/* Generates an .exp filename following the scheme:
 *	<fileroot>[-<extra>].exp
 */
static char *expfilename(struct parser *p, const char *extra)
{
	char *filename;
	/* reserve enough space to hold the string
	 *   "-cpu_fffff_mmm_sss" + 1 for the trailing null character.
	 */
	char cpu_suffix[19];
	size_t n;

	if (!extra)
		extra = "";
	*cpu_suffix = '\0';

	/* determine length of resulting filename, which looks like:
	 *   <fileroot>[-<extra>][-cpu_<f>_<m>_<s>].exp
	 */
	n = strlen(p->y->fileroot);

	if (*extra != '\0')
		/* the extra string is prepended with a -.  */
		n += 1 + strlen(extra);

	if (p->conf->cpu.vendor != pcv_unknown) {
		struct pt_cpu cpu;

		cpu = p->conf->cpu;
		if (cpu.stepping)
			n += sprintf(cpu_suffix,
				     "-cpu_%" PRIu16 "_%" PRIu8 "_%" PRIu8 "",
				     cpu.family, cpu.model, cpu.stepping);
		else
			n += sprintf(cpu_suffix,
				     "-cpu_%" PRIu16 "_%" PRIu8 "", cpu.family,
				     cpu.model);
	}

	n += strlen(exp_suffix);

	/* trailing null character.  */
	n += 1;

	filename = malloc(n);
	if (!filename)
		return NULL;

	strcpy(filename, p->y->fileroot);
	if (*extra != '\0') {
		strcat(filename, "-");
		strcat(filename, extra);
	}
	strcat(filename, cpu_suffix);
	strcat(filename, exp_suffix);

	return filename;
}

/* Returns true if @c is part of a label; false otherwise.  */
static int islabelchar(int c)
{
	if (isalnum(c))
		return 1;

	switch (c) {
	case '_':
		return 1;
	}

	return 0;
}

/* Generates the content of the .exp file by printing all lines with
 * everything up to and including the first comment semicolon removed.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 * Returns -err_internal if @p is the NULL pointer.
 * Returns -err_file_write if the .exp file could not be fully written.
 */
static int p_gen_expfile(struct parser *p)
{
	int errcode;
	enum { slen = 1024 };
	char s[slen];
	struct pt_directive *pd;
	char *filename;
	FILE *f;

	if (bug_on(!p))
		return -err_internal;

	pd = p->pd;

	/* the directive in the current line must be the .exp directive.  */
	errcode = yasm_pd_parse(p->y, pd);
	if (bug_on(errcode < 0))
		return -err_internal;

	if (bug_on(strcmp(pd->name, ".exp") != 0))
		return -err_internal;

	filename = expfilename(p, pd->payload);
	if (!filename)
		return -err_no_mem;
	f = fopen(filename, "w");
	if (!f) {
		free(filename);
		return -err_file_open;
	}

	for (;;) {
		int i;
		char *line, *comment;

		errcode = yasm_next_line(p->y, s, slen);
		if (errcode < 0)
			break;

		errcode = yasm_pd_parse(p->y, pd);
		if (errcode < 0 && errcode != -err_no_directive)
			break;

		if (errcode == 0 && strcmp(pd->name, ".exp") == 0) {
			fclose(f);
			printf("%s\n", filename);
			free(filename);
			filename = expfilename(p, pd->payload);
			if (!filename)
				return -err_no_mem;
			f = fopen(filename, "w");
			if (!f) {
				free(filename);
				return -err_file_open;
			}
			continue;
		}

		line = strchr(s, ';');
		if (!line)
			continue;

		line += 1;

		comment = strchr(line, '#');
		if (comment)
			*comment = '\0';

		/* remove trailing spaces.  */
		for (i = (int) strlen(line)-1; i >= 0 && isspace(line[i]); i--)
			line[i] = '\0';

		for (;;) {
			char *tmp, label[256];
			uint64_t addr;
			int i, zero_padding, qmark_padding, qmark_size, status;

			zero_padding = 0;
			qmark_padding = 0;
			qmark_size = 0;
			status = 0;

			/* find the label character in the string.
			 * if there is no label character, we just print
			 * the rest of the line and end.
			 */
			tmp = strchr(line, '%');
			if (!tmp) {
				if (fprintf(f, "%s", line) < 0) {
					errcode = -err_file_write;
					goto error;
				}
				break;
			}

			/* make the label character a null byte and
			 * print the first portion, which does not
			 * belong to the label into the file.
			 */
			*tmp = '\0';
			if (fprintf(f, "%s", line) < 0) {
				errcode = -err_file_write;
				goto error;
			}

			/* test if there is a valid label name after the %.  */
			line = tmp+1;
			if (*line == '\0' || isspace(*line)) {
				errcode = -err_no_label;
				goto error;
			}

			/* check if zero padding is requested.  */
			if (*line == '0') {
				zero_padding = 1;
				line += 1;
			}
			/* chek if ? padding is requested.  */
			else if (*line == '?') {
				qmark_padding = 1;
				zero_padding = 1;
				qmark_size = 0;
				line += 1;
			}

			/* advance i to the first non alpha-numeric
			 * character. all characters everything from
			 * line[0] to line[i-1] belongs to the label
			 * name.
			 */
			for (i = 0; islabelchar(line[i]); i++)
				;

			if (i > 255) {
				errcode = -err_label_name;
				goto error;
			}
			strncpy(label, line, i);
			label[i] = '\0';

			/* advance to next character.  */
			line = &line[i];

			/* lookup the label name and print it to the
			 * output file.
			 */
			errcode = yasm_lookup_label(p->y, &addr, label);
			if (errcode < 0) {
				errcode = l_lookup(p->pt_labels, &addr, label);
				if (errcode < 0)
					goto error;

				if (zero_padding)
					status = fprintf(f, "%016" PRIx64, addr);
				else
					status = fprintf(f, "%" PRIx64, addr);

				if (status < 0) {
					errcode = -err_file_write;
					goto error;
				}

				continue;
			}

			/* check if masking is requested.  */
			if (*line == '.') {
				char *endptr;
				long int n;

				line += 1;

				n = strtol(line, &endptr, 0);
				/* check if strtol made progress and
				 * stops on a space or null byte.
				 * otherwise the int could not be
				 * parsed.
				 */
				if (line == endptr ||
				    (*endptr != '\0' && !isspace(*endptr)
				     && !ispunct(*endptr))) {
					errcode = -err_parse_int;
					goto error;
				}
				addr &= (1ull << (n << 3)) - 1ull;
				line = endptr;

				qmark_size = 8 - n;
			}

			if (qmark_padding) {
				int i;

				for (i = 0; i < qmark_size; ++i) {
					status = fprintf(f, "??");
					if (status < 0) {
						errcode = -err_file_write;
						goto error;
					}
				}

				for (; i < 8; ++i) {
					uint8_t byte;

					byte = (uint8_t)(addr >> ((7 - i) * 8));

					status = fprintf(f, "%02" PRIx8, byte);
					if (status < 0) {
						errcode = -err_file_write;
						goto error;
					}
				}
			} else if (zero_padding)
				status = fprintf(f, "%016" PRIx64, addr);
			else
				status = fprintf(f, "%" PRIx64, addr);

			if (status < 0) {
				errcode = -err_file_write;
				goto error;
			}

		}

		if (fprintf(f, "\n") < 0) {
			errcode = -err_file_write;
			goto error;
		}
	}

error:

	fclose(f);
	if (errcode < 0 && errcode != -err_out_of_range) {
		fprintf(stderr, "fatal: %s could not be created:\n", filename);
		yasm_print_err(p->y, "", errcode);
		remove(filename);
	} else
		printf("%s\n", filename);
	free(filename);

	/* If there are no lines left, we are done.  */
	if (errcode == -err_out_of_range)
		return 0;

	return errcode;
}

static void p_close_files(struct parser *p)
{
	if (p->ptfile) {
		fclose(p->ptfile);
		p->ptfile = NULL;
	}
}

static int p_open_files(struct parser *p)
{
	p->ptfile = fopen(p->ptfilename, "wb");
	if (!p->ptfile) {
		fprintf(stderr, "open %s failed\n", p->ptfilename);
		goto error;
	}
	return 0;

error:
	p_close_files(p);
	return -err_file_open;
}

/* Processes the current directive.
 * If the encoder returns an error, a message including current file and
 * line number together with the pt error string is printed on stderr.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 * Returns -err_internal if @p or @e is the NULL pointer.
 * Returns -err_parse_missing_directive if there was a pt directive marker,
 * but no directive.
 * Returns -stop_process if the .exp directive was encountered.
 * Returns -err_pt_lib if the pt encoder returned an error.
 * Returns -err_parse if a general parsing error was encountered.
 * Returns -err_parse_unknown_directive if there was an unknown pt directive.
 */
static int p_process(struct parser *p, struct pt_encoder *e)
{
	int bytes_written;
	int errcode;
	char *directive, *payload, *pt_label_name, *tmp;
	struct pt_directive *pd;
	struct pt_packet packet;

	if (bug_on(!p))
		return -err_internal;

	if (bug_on(!e))
		return -err_internal;

	pd = p->pd;
	if (!pd)
		return -err_internal;

	directive = pd->name;
	payload = pd->payload;

	pt_label_name = NULL;
	bytes_written = 0;
	errcode = 0;

	/* find a label name.  */
	tmp = strchr(directive, ':');
	if (tmp) {
		uint64_t x;

		pt_label_name = directive;
		directive = tmp+1;
		*tmp = '\0';

		/* ignore whitespace between label and directive. */
		while (isspace(*directive))
			directive += 1;

		/* if we can lookup a yasm label with the same name, the
		 * current pt directive label is invalid.  */
		errcode = yasm_lookup_label(p->y, &x, pt_label_name);
		if (errcode == 0)
			errcode = -err_label_not_unique;

		if (errcode != -err_no_label)
			return yasm_print_err(p->y, "label lookup",
					      errcode);

		/* if we can lookup a pt directive label with the same
		 * name, the current pt directive label is invalid.  */
		errcode = l_lookup(p->pt_labels, &x, pt_label_name);
		if (errcode == 0)
			errcode = -err_label_not_unique;

		if (errcode != -err_no_label)
			return yasm_print_err(p->y, "label lookup",
					      -err_label_not_unique);
	}

	/* now try to match the directive string and call the
	 * corresponding function that parses the payload and emits an
	 * according packet.
	 */
	if (strcmp(directive, "") == 0)
		return yasm_print_err(p->y, "invalid syntax",
				      -err_parse_missing_directive);
	else if (strcmp(directive, ".exp") == 0) {
		/* this is the end of processing pt directives, so we
		 * add a p_last label to the pt directive labels.
		 */
		errcode = l_append(p->pt_labels, "eos", p->pt_bytes_written);
		if (errcode < 0)
			return yasm_print_err(p->y, "append label", errcode);

		return -stop_process;
	}

	if (strcmp(directive, "psb") == 0) {
		errcode = parse_empty(payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "psb: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_psb;
	} else if (strcmp(directive, "psbend") == 0) {
		errcode = parse_empty(payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "psbend: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_psbend;
	} else if (strcmp(directive, "pad") == 0) {
		errcode = parse_empty(payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "pad: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_pad;
	} else if (strcmp(directive, "ovf") == 0) {
		errcode = parse_empty(payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "ovf: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_ovf;
	} else if (strcmp(directive, "stop") == 0) {
		errcode = parse_empty(payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "stop: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_stop;
	} else if (strcmp(directive, "tnt") == 0) {
		errcode = parse_tnt(&packet.payload.tnt.payload,
				    &packet.payload.tnt.bit_size, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tnt: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_tnt_8;
	} else if (strcmp(directive, "tnt64") == 0) {
		errcode = parse_tnt(&packet.payload.tnt.payload,
				    &packet.payload.tnt.bit_size, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tnt64: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_tnt_64;
	} else if (strcmp(directive, "tip") == 0) {
		errcode = parse_ip(p, &packet.payload.ip.ip,
				   &packet.payload.ip.ipc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tip: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_tip;
	} else if (strcmp(directive, "tip.pge") == 0) {
		errcode = parse_ip(p, &packet.payload.ip.ip,
				   &packet.payload.ip.ipc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tip.pge: parsing failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_tip_pge;
	} else if (strcmp(directive, "tip.pgd") == 0) {
		errcode = parse_ip(p, &packet.payload.ip.ip,
				   &packet.payload.ip.ipc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tip.pgd: parsing failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_tip_pgd;
	} else if (strcmp(directive, "fup") == 0) {
		errcode = parse_ip(p, &packet.payload.ip.ip,
				   &packet.payload.ip.ipc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "fup: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_fup;
	} else if (strcmp(directive, "mode.exec") == 0) {
		if (strcmp(payload, "16bit") == 0) {
			packet.payload.mode.bits.exec.csl = 0;
			packet.payload.mode.bits.exec.csd = 0;
		} else if (strcmp(payload, "64bit") == 0) {
			packet.payload.mode.bits.exec.csl = 1;
			packet.payload.mode.bits.exec.csd = 0;
		} else if (strcmp(payload, "32bit") == 0) {
			packet.payload.mode.bits.exec.csl = 0;
			packet.payload.mode.bits.exec.csd = 1;
		} else {
			errcode = yasm_print_err(p->y,
						 "mode.exec: argument must be one of \"16bit\", \"64bit\" or \"32bit\"",
						 -err_parse);
			goto error;
		}
		packet.payload.mode.leaf = pt_mol_exec;
		packet.type = ppt_mode;
	} else if (strcmp(directive, "mode.tsx") == 0) {
		if (strcmp(payload, "begin") == 0) {
			packet.payload.mode.bits.tsx.intx = 1;
			packet.payload.mode.bits.tsx.abrt = 0;
		} else if (strcmp(payload, "abort") == 0) {
			packet.payload.mode.bits.tsx.intx = 0;
			packet.payload.mode.bits.tsx.abrt = 1;
		} else if (strcmp(payload, "commit") == 0) {
			packet.payload.mode.bits.tsx.intx = 0;
			packet.payload.mode.bits.tsx.abrt = 0;
		} else {
			errcode = yasm_print_err(p->y,
						 "mode.tsx: argument must be one of \"begin\", \"abort\" or \"commit\"",
						 -err_parse);
			goto error;
		}
		packet.payload.mode.leaf = pt_mol_tsx;
		packet.type = ppt_mode;
	} else if (strcmp(directive, "pip") == 0) {
		const char *modifier;

		errcode = parse_uint64(&packet.payload.pip.cr3, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "pip: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_pip;
		packet.payload.pip.nr = 0;

		modifier = strtok(NULL, " ,");
		if (modifier) {
			if (strcmp(modifier, "nr") == 0)
				packet.payload.pip.nr = 1;
			else {
				yasm_print_err(p->y, "pip: parsing failed",
					       -err_parse_trailing_tokens);
				goto error;
			}
		}
	} else if (strcmp(directive, "tsc") == 0) {
		errcode = parse_uint64(&packet.payload.tsc.tsc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tsc: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_tsc;
	} else if (strcmp(directive, "cbr") == 0) {
		errcode = parse_uint8(&packet.payload.cbr.ratio, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "cbr: parsing cbr failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_cbr;
	} else if (strcmp(directive, "tma") == 0) {
		errcode = parse_tma(&packet.payload.tma.ctc,
				    &packet.payload.tma.fc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "tma: parsing tma failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_tma;
	} else if (strcmp(directive, "mtc") == 0) {
		errcode = parse_uint8(&packet.payload.mtc.ctc, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "mtc: parsing mtc failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_mtc;
	} else if (strcmp(directive, "cyc") == 0) {
		errcode = parse_uint64(&packet.payload.cyc.value, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "cyc: parsing cyc failed",
				       errcode);
			goto error;
		}
		packet.type = ppt_cyc;
	} else if (strcmp(directive, "vmcs") == 0) {
		errcode = parse_uint64(&packet.payload.vmcs.base, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "vmcs: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_vmcs;
	} else if (strcmp(directive, "mnt") == 0) {
		errcode = parse_uint64(&packet.payload.mnt.payload, payload);
		if (errcode < 0) {
			yasm_print_err(p->y, "mnt: parsing failed", errcode);
			goto error;
		}
		packet.type = ppt_mnt;
	} else {
		errcode = yasm_print_err(p->y, "invalid syntax",
					 -err_parse_unknown_directive);
		goto error;
	}

	bytes_written = pt_enc_next(e, &packet);
	if (bytes_written < 0) {
		const char *errstr, *format;
		char *msg;
		size_t n;

		errstr = pt_errstr(pt_errcode(bytes_written));
		format = "encoder error in directive %s (status %s)";
		/* the length of format includes the "%s" (-2)
		 * characters, we add errstr (+-0) and then we need
		 * space for a terminating null-byte (+1).
		 */
		n = strlen(format)-4 + strlen(directive) + strlen(errstr) + 1;

		msg = malloc(n);
		if (!msg)
			errcode = yasm_print_err(p->y,
				       "encoder error not enough memory to show error code",
				       -err_pt_lib);
		else {
			sprintf(msg, format, directive, errstr);
			errcode = yasm_print_err(p->y, msg, -err_pt_lib);
			free(msg);
		}
	} else {
		if (pt_label_name) {
			errcode = l_append(p->pt_labels, pt_label_name,
					   p->pt_bytes_written);
			if (errcode < 0)
				goto error;
		}
		p->pt_bytes_written += bytes_written;
	}

error:
	if (errcode < 0)
		bytes_written = errcode;
	return bytes_written;
}

/* Starts the parsing process.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 * Returns -err_pt_lib if the pt encoder could not be initialized.
 * Returns -err_file_write if the .pt or .exp file could not be fully
 * written.
 */
int p_start(struct parser *p)
{
	int errcode;

	if (bug_on(!p))
		return -err_internal;

	errcode = yasm_parse(p->y);
	if (errcode < 0)
		return errcode;

	for (;;) {
		int bytes_written;
		struct pt_encoder *e;

		errcode = yasm_next_pt_directive(p->y, p->pd);
		if (errcode < 0)
			break;

		e = pt_alloc_encoder(p->conf);
		if (!e) {
			fprintf(stderr, "pt_alloc_encoder failed\n");
			errcode = -err_pt_lib;
			break;
		}

		bytes_written = p_process(p, e);

		pt_free_encoder(e);

		if (bytes_written == -stop_process) {
			errcode = p_gen_expfile(p);
			break;
		}
		if (bytes_written < 0) {
			errcode = bytes_written;
			break;
		}
		if (fwrite(p->conf->begin, 1, bytes_written, p->ptfile)
		    != (size_t)bytes_written) {
			fprintf(stderr, "write %s failed", p->ptfilename);
			errcode = -err_file_write;
			break;
		}
	}

	/* If there is no directive left, there's nothing more to do.  */
	if (errcode == -err_no_directive)
		return 0;

	return errcode;
}

int parse(const char *pttfile, const struct pt_config *conf)
{
	int errcode;
	struct parser *p;

	p = p_alloc(pttfile, conf);
	if (!p)
		return -err_no_mem;

	errcode = p_open_files(p);
	if (errcode < 0)
		goto error;

	errcode = p_start(p);
	p_close_files(p);

error:
	p_free(p);
	return errcode;
}

int parse_empty(char *payload)
{
	if (!payload)
		return 0;

	strtok(payload, " ");
	if (!payload || *payload == '\0')
		return 0;

	return -err_parse_trailing_tokens;
}

int parse_tnt(uint64_t *tnt, uint8_t *size, char *payload)
{
	char c;

	if (bug_on(!size))
		return -err_internal;

	if (bug_on(!tnt))
		return -err_internal;

	*size = 0;
	*tnt = 0ull;

	if (!payload)
		return 0;

	while (*payload != '\0') {
		c = *payload;
		payload++;
		if (isspace(c) || c == '.')
			continue;
		*size += 1;
		*tnt <<= 1;
		switch (c) {
		case 'n':
			break;
		case 't':
			*tnt |= 1;
			break;
		default:
			return -err_parse_unknown_char;
		}
	}

	return 0;
}

static int check_ipc(enum pt_ip_compression ipc)
{
	switch (ipc) {
	case pt_ipc_suppressed:
	case pt_ipc_update_16:
	case pt_ipc_update_32:
	case pt_ipc_update_48:
	case pt_ipc_sext_48:
	case pt_ipc_full:
		return 0;
	}
	return -err_parse_ipc;
}

int parse_ip(struct parser *p, uint64_t *ip, enum pt_ip_compression *ipc,
	     char *payload)
{
	int errcode;
	char *endptr;

	if (bug_on(!ip))
		return -err_internal;

	if (bug_on(!ipc))
		return -err_internal;

	*ipc = pt_ipc_suppressed;
	*ip = 0;

	payload = strtok(payload, " :");
	if (!payload || *payload == '\0')
		return -err_parse_no_args;

	*ipc = (enum pt_ip_compression) strtol(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_ipc;

	/* is ipc valid?  */
	errcode = check_ipc(*ipc);
	if (errcode < 0)
		return errcode;

	payload = strtok(NULL, " :");
	if (!payload)
		return -err_parse_ip_missing;

	/* can be resolved to a label?  */
	if (*payload == '%') {
		int errcode;

		if (!p)
			return -err_internal;

		errcode = yasm_lookup_label(p->y, ip, payload + 1);
		if (errcode < 0)
			return errcode;
	} else {
		/* can be parsed as address?  */
		int errcode;

		errcode = str_to_uint64(payload, ip);
		if (errcode < 0)
			return errcode;
	}

	/* no more tokens left.  */
	payload = strtok(NULL, " ");
	if (payload)
		return -err_parse_trailing_tokens;

	return 0;
}

int parse_uint64(uint64_t *x, char *payload)
{
	int errcode;

	if (bug_on(!x))
		return -err_internal;

	payload = strtok(payload, " ,");
	if (!payload)
		return -err_parse_no_args;

	errcode = str_to_uint64(payload, x);
	if (errcode < 0)
		return errcode;

	return 0;
}

int parse_uint8(uint8_t *x, char *payload)
{
	char *endptr;
	long int i;

	if (bug_on(!x))
		return -err_internal;

	payload = strtok(payload, " ,");
	if (!payload)
		return -err_parse_no_args;

	i = strtol(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_int;

	if (i > 0xff)
		return -err_parse_int_too_big;

	*x = (uint8_t)i;

	return 0;
}

int parse_uint16(uint16_t *x, char *payload)
{
	char *endptr;
	long int i;

	if (bug_on(!x))
		return -err_internal;

	payload = strtok(payload, " ,");
	if (!payload)
		return -err_parse_no_args;

	i = strtol(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_int;

	if (i > 0xffffl)
		return -err_parse_int_too_big;

	*x = (uint16_t)i;

	return 0;
}

int parse_uint32(uint32_t *x, char *payload)
{
	char *endptr;
	long long int i;

	if (bug_on(!x))
		return -err_internal;

	payload = strtok(payload, " ,");
	if (!payload)
		return -err_parse_no_args;

	i = strtoll(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_int;

	if (i > 0xffffffffll)
		return -err_parse_int_too_big;

	*x = (uint32_t)i;

	return 0;
}

int parse_tma(uint16_t *ctc, uint16_t *fc, char *payload)
{
	char *endptr;
	long int i;

	if (bug_on(!ctc || !fc))
		return -err_internal;

	payload = strtok(payload, ",");
	if (!payload || *payload == '\0')
		return -err_parse_no_args;

	i = strtol(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_int;

	if (i > 0xffffl)
		return -err_parse_int_too_big;

	*ctc = (uint16_t)i;

	payload = strtok(NULL, " ,");
	if (!payload)
		return -err_parse_no_args;

	i = strtol(payload, &endptr, 0);
	if (payload == endptr || *endptr != '\0')
		return -err_parse_int;

	if (i > 0xffffl)
		return -err_parse_int_too_big;

	*fc = (uint16_t)i;

	/* no more tokens left.  */
	payload = strtok(NULL, " ");
	if (payload)
		return -err_parse_trailing_tokens;

	return 0;
}
