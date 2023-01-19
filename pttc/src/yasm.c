/*
 * Copyright (c) 2013-2023, Intel Corporation
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

#include "errcode.h"
#include "file.h"
#include "util.h"
#include "yasm.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#  define snprintf _snprintf_c
#endif


static int create_section_label_name(char *label, size_t size,
				     const char *name, const char *attribute)
{
	int written;

	written = snprintf(label, size, "section_%s_%s", name, attribute);
	if ((written < 0) || (size <= (size_t) written))
		return -err_no_mem;

	return 0;
}

static int add_section_label(struct label *l, const char *name,
			     const char *attribute, uint64_t value,
			     struct label **length)
{
	char label[255];
	int errcode;

	errcode = create_section_label_name(label, sizeof(label), name,
					    attribute);
	if (errcode < 0)
		return errcode;

	errcode = l_append(l, label, value);
	if (errcode < 0)
		return errcode;

	if (length)
		*length = l_find(l, label);

	return 0;
}

static int parse_section_label(struct label *l, const char *name,
			       const char *attribute)
{
	uint64_t addr;
	char *value;

	value = strtok(NULL, " ]");
	if (!value)
		return -err_section_attribute_no_value;

	if (sscanf(value, "%" PRIx64, &addr) != 1)
		return -err_parse_int;

	return add_section_label(l, name, attribute, addr, NULL);
}

static int parse_section(char *line, struct label *l, struct label **length)
{
	char *name, *attribute;
	int errcode;

	name = strtok(line, " ");
	if (!name)
		return -err_section_no_name;

	/* we initialize the section's length to zero - it will be updated
	 * when we process the section's content.
	 */
	errcode = add_section_label(l, name, "length", 0ull, length);
	if (errcode < 0)
		return errcode;

	for (;;) {
		attribute = strtok(NULL, " =]");
		if (!attribute)
			return 0;

		if (strcmp(attribute, "start") == 0) {
			errcode = parse_section_label(l, name, "start");
			if (errcode < 0)
				return errcode;
		} else if (strcmp(attribute, "vstart") == 0) {
			errcode = parse_section_label(l, name, "vstart");
			if (errcode < 0)
				return errcode;
		} else
			return -err_section_unknown_attribute;
	}
}

static int lookup_section_label(struct label *l, const char *name,
				const char *attribute, uint64_t *value)
{
	char label[255];
	int errcode;

	errcode = create_section_label_name(label, sizeof(label), name,
					    attribute);
	if (errcode < 0)
		return errcode;

	return l_lookup(l, value, label);
}

static int lookup_section_vstart(struct label *l, char *line,
				 uint64_t *vstart)
{
	char *name;

	name = strtok(line, " ");
	if (!name)
		return -err_section_no_name;

	return lookup_section_label(l, name, "vstart", vstart);
}

static const char key_section[] = "[section";
static const char key_org[] = "[org";

int parse_yasm_labels(struct label *l, const struct text *t)
{
	int errcode, no_org_directive;
	size_t i;
	uint64_t base_addr;
	char line[1024], *end;
	struct label *length;

	if (bug_on(!t))
		return -err_internal;

	base_addr = 0;
	no_org_directive = 1;
	length = NULL;
	end = line + sizeof(line);

	/* determine base address from org directive and insert special
	 * section labels.
	 */
	for (i = 0; i < t->n; i++) {
		char *tmp;

		errcode = text_line(t, line, sizeof(line), i);
		if (errcode < 0)
			return errcode;

		tmp = strstr(line, key_section);
		if (tmp) {
			tmp += sizeof(key_section) - 1;
			errcode = parse_section(tmp, l, &length);
			if (errcode < 0)
				return errcode;
			continue;
		}

		tmp = strstr(line, key_org);
		if (tmp) {
			char *org;

			org = tmp + sizeof(key_org) - 1;
			tmp = strstr(org, "]");
			if (!tmp)
				return -err_no_org_directive;

			*tmp = 0;

			errcode = str_to_uint64(org, &base_addr, 0);
			if (errcode < 0)
				return errcode;

			errcode = l_append(l, "org", base_addr);
			if (errcode < 0)
				return errcode;

			no_org_directive = 0;
			continue;
		}

		/* update the section_<name>_length label, if we have one.
		 *
		 * this must be last; it destroys @line.
		 */
		if (length) {
			uint64_t value, size;

			tmp = strtok(line, " ");
			if (!tmp)
				continue;

			/* we expect a line number. */
			errcode = str_to_uint64(tmp, &value, 10);
			if (errcode < 0)
				continue;

			tmp = strtok(NULL, " ");
			if (!tmp)
				continue;

			/* we expect an address. */
			errcode = str_to_uint64(tmp, &value, 16);
			if (errcode < 0)
				continue;

			tmp = strtok(NULL, " ");
			if (!tmp)
				continue;

			/* we expect an opcode. */
			errcode = str_to_uint64(tmp, &value, 16);
			if (errcode < 0)
				continue;

			/* we got an opcode - let's compute it's size. */
			for (size = 0; value != 0; value >>= 8)
				size += 1;

			/* update the section_<name>_length label. */
			length->addr += size;
		}
	}

	if (no_org_directive)
		return -err_no_org_directive;

	for (i = 0; i < t->n; i++) {
		char *tmp;
		uint64_t addr;

		errcode = text_line(t, line, sizeof(line), i);
		if (errcode < 0)
			goto error;

		/* Change the base on section switches. */
		tmp = strstr(line, key_section);
		if (tmp) {
			tmp += sizeof(key_section) - 1;
			errcode = lookup_section_vstart(l, tmp, &base_addr);
			if (errcode < 0)
				return errcode;
			continue;
		}

		/* skip line number count.  */
		tmp = strtok(line, " ");
		if (!tmp)
			continue;

		/* the label can now be on the same line as the memory
		 * address or on a line by its own.
		 * we look at the next token and (1) if it looks like a
		 * label, we search in the following lines for the
		 * corresponding address; or (2) if it looks like an
		 * address, we store it and see if the token after the
		 * opcode looks like a token; or (3) none of the above,
		 * we continue with the next line.
		 */

		/* second token after the line number count.  it's
		 * either an address; or a label.
		 */
		tmp = strtok(NULL, " ");
		if (!tmp)
			continue;

		if (!make_label(tmp, end)) {
			uint64_t laddr;

			/* get address in case we find a label later.  */
			if (sscanf(tmp, "%" PRIx64, &addr) != 1)
				continue;

			/* skip the opcode token.  */
			tmp = strtok(NULL, " ");
			if (!tmp)
				continue;

			/* this might be a label now.  */
			tmp = strtok(NULL, " ");
			if (!make_label(tmp, end))
				continue;

			laddr = addr + base_addr;
			if (laddr < base_addr) {
				errcode = -err_label_addr;
				goto error;
			}

			errcode = l_append(l, tmp, laddr);
			if (errcode < 0)
				goto error;
			continue;
		}

		/* there was a label so now an address needs to
		 * be found.
		 */
		errcode = -err_label_addr;
		for (i += 1; i < t->n; i++) {
			int errcode_text;

			errcode_text = text_line(t, line, sizeof(line), i);
			if (errcode_text < 0) {
				errcode = errcode_text;
				break;
			}
			if (sscanf(line, "%*d %" PRIx64 " %*x %*s", &addr)
			    == 1) {
				uint64_t laddr;

				laddr = addr + base_addr;
				if (laddr < base_addr) {
					errcode = -err_label_addr;
					break;
				}

				errcode = l_append(l, tmp, laddr);
				break;
			}
		}
		if (errcode == -err_label_addr)
			fprintf(stderr, "label '%s' has no address\n", tmp);

		if (errcode < 0)
			goto error;
	}

	return 0;

error:
	l_free(l->next);
	free(l->name);
	l->next = NULL;
	l->name = NULL;
	return errcode;
}

int make_label(char *s, const char *end)
{
	size_t n, size;

	if (bug_on(!s))
		return 0;

	if (bug_on(end <= s))
		return 0;

	size = (size_t) ((uintptr_t) end - (uintptr_t) s);
	n = strnlen(s, size);
	if (size <= n)
		return 0;

	if (n == 0 || s[n-1] != ':')
		return 0;

	s[n-1] = '\0';
	return 1;
}

struct state *st_alloc(void)
{
	return calloc(1, sizeof(struct state));
}

void st_free(struct state *st)
{
	if (!st)
		return;

	free(st->filename);
	free(st->line);
	free(st);
}

int st_print_err(const struct state *st, const char *s, int errcode)
{
	if (bug_on(!st))
		return -err_internal;

	if (bug_on(!(-err_max < errcode && errcode < 0)))
		return -err_internal;

	if (!s)
		s = "";

	fprintf(stderr, "%s:%d: error: %s (%s)\n", st->filename, st->n-1, s,
		errstr[-errcode]);

	return errcode;
}

/* Sets current @filename, increment (@inc) and line number (@n) in @st.
 *
 * Note that @filename, @inc and @n correspond to the yasm .lst file
 * source file information.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 */
static int st_set_file(struct state *st, const char *filename, int inc, int n)
{
	int errcode;

	if (bug_on(!st))
		return -err_internal;

	if (bug_on(!filename))
		return -err_internal;

	free(st->filename);
	errcode = duplicate_name(&st->filename, filename, FILENAME_MAX);
	if (errcode < 0)
		return errcode;

	st->inc = inc;
	st->n = n;
	return 0;
}

/* Sets current line in @st to @s and increases the line number.
 *
 * Returns 0 on success; a negative enum errcode otherwise.
 */
static int st_update(struct state *st, const char *s)
{
	int errcode;

	free(st->line);
	st->line = NULL;

	errcode = duplicate_name(&st->line, s, FILENAME_MAX);
	if (errcode < 0)
		return errcode;

	st->n += st->inc;
	return 0;
}

struct pt_directive *pd_alloc(size_t n)
{
	struct pt_directive *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	pd->name = malloc(n);
	if (!pd->name)
		goto error;

	pd->payload = malloc(n);
	if (!pd->payload)
		goto error;

	pd->nlen = n;
	pd->plen = n;

	return pd;

error:
	pd_free(pd);
	return NULL;
}

void pd_free(struct pt_directive *pd)
{
	if (!pd)
		return;

	free(pd->name);
	free(pd->payload);
	free(pd);
}

int pd_set(struct pt_directive *pd, enum pt_directive_kind kind,
	   const char *name, const char *payload)
{
	if (bug_on(!pd))
		return -err_internal;

	if (bug_on(!name))
		return -err_internal;

	if (bug_on(!payload))
		return -err_internal;

	pd->kind = kind;
	strncpy(pd->name, name, pd->nlen);
	if (pd->nlen > 0)
		pd->name[pd->nlen - 1] = '\0';
	strncpy(pd->payload, payload, pd->plen);
	if (pd->plen > 0)
		pd->payload[pd->plen - 1] = '\0';

	return 0;
}

/* Magic annotation markers.  */
static const char pt_marker[] = "@pt ";

#if defined(FEATURE_SIDEBAND)
static const char sb_marker[] = "@sb ";
#endif

int pd_parse(struct pt_directive *pd, struct state *st)
{
	enum pt_directive_kind kind;
	char *line, *comment, *openpar, *closepar, *directive, *payload;
	int errcode;
	char *c;

	if (bug_on(!pd))
		return -err_internal;

	if (bug_on(!st))
		return -err_internal;


	errcode = duplicate_name(&line, st->line, FILENAME_MAX);
	if (errcode < 0)
		return errcode;

	/* make line lower case.  */
	for (c = line; *c; ++c)
		*c = (char) tolower(*c);

	/* if the current line is not a comment or contains no magic marker
	 * -err_no_directive is returned.
	 */
	errcode = -err_no_directive;

	/* search where the comment begins.  */
	comment = strchr(line, ';');

	/* if there is no comment in the line, we don't have anything to
	 * do.
	 */
	if (!comment)
		goto cleanup;

	/* search for @pt marker.  */
	directive = strstr(comment+1, pt_marker);
	if (directive) {
		directive += sizeof(pt_marker) - 1;
		kind = pdk_pt;
	} else {
#if defined(FEATURE_SIDEBAND)
		/* search for @sb marker. */
		directive = strstr(comment+1, sb_marker);
		if (directive) {
			directive += sizeof(sb_marker) - 1;
			kind = pdk_sb;
		} else
#endif
			goto cleanup;
	}

	/* skip leading whitespace. */
	while (isspace(*directive))
		directive += 1;

	/* directive found, now parse the payload.  */
	errcode = 0;

	/* find position of next '(', separating the directive and the
	 * payload.
	 */
	openpar = strchr(directive, '(');
	if (!openpar) {
		errcode = -err_missing_openpar;
		st_print_err(st, "invalid syntax", errcode);
		goto cleanup;
	}

	/* find position of next ')', marking the end of the payload */
	closepar = strchr(openpar, ')');
	if (!closepar) {
		errcode = -err_missing_closepar;
		st_print_err(st, "invalid syntax", errcode);
		goto cleanup;
	}

	/* make "multiple" strings by artificially terminating them with
	 * '\0' then get directive and payload substrings, which will
	 * have leading and trailing whitespace "removed".
	 */
	*openpar = '\0';
	*closepar = '\0';

	payload = openpar+1;

	errcode = pd_set(pd, kind, directive, payload);

cleanup:
	free(line);
	return errcode;
}

static const char bin_suffix[] = ".bin";
static const char lst_suffix[] = ".lst";
static const char path_separator = '/';

struct yasm *yasm_alloc(const char *pttfile)
{
	char *tmp;
	size_t flen, binsize, lstsize;
	struct yasm *y;
	int errcode, len;

	if (bug_on(!pttfile))
		return NULL;

	y = calloc(1, sizeof(*y));
	if (!y)
		return NULL;

	y->fl = fl_alloc();
	if (!y->fl)
		goto error;

	y->st_asm = st_alloc();
	if (!y->st_asm)
		goto error;

	errcode = duplicate_name(&y->fileroot, pttfile, FILENAME_MAX);
	if (errcode < 0)
		goto error;

	errcode = duplicate_name(&y->pttfile, pttfile, FILENAME_MAX);
	if (errcode < 0)
		goto error;

	tmp = strrchr(y->fileroot, '.');
	if (tmp)
		*tmp = '\0';

	tmp = strrchr(y->fileroot, path_separator);
	if (tmp) {
		tmp += 1;

		flen = strnlen(tmp, FILENAME_MAX);
		if (FILENAME_MAX <= flen)
			goto error;

		memmove(y->fileroot, tmp, flen);
		y->fileroot[flen] = '\0';
	}

	flen = strnlen(y->fileroot, FILENAME_MAX);
	if (FILENAME_MAX <= flen)
		goto error;

	binsize = flen + sizeof(bin_suffix);
	lstsize = flen + sizeof(lst_suffix);

	y->binfile = malloc(binsize);
	if (!y->binfile)
		goto error;

	len = snprintf(y->binfile, binsize, "%s%s", y->fileroot, bin_suffix);
	if ((len < 0) || ((size_t) len != (binsize - 1)))
		goto error;

	y->lstfile = malloc(lstsize);
	if (!y->lstfile)
		goto error;

	len = snprintf(y->lstfile, lstsize, "%s%s", y->fileroot, lst_suffix);
	if ((len < 0) || ((size_t) len != (lstsize - 1)))
		goto error;

	y->l = l_alloc();
	if (!y->l)
		goto error;

	return y;

error:
	yasm_free(y);
	return 0;
}

static int yasm_run(struct yasm *y)
{
	char *argv[] = {
		"yasm",
		"<pttfile>",
		"-f", "bin",
		"-o", "<binfile>",
		"-L", "nasm",
		"-l", "<lstfile>",
		NULL,
	};

	argv[1] = y->pttfile;
	argv[5] = y->binfile;
	argv[9] = y->lstfile;

	return run(argv[0], argv);
}

int yasm_parse(struct yasm *y)
{
	int errcode;
	const struct text *t;

	if (bug_on(!y))
		return -err_internal;

	errcode = yasm_run(y);
	if (errcode < 0)
		goto error;

	errcode = fl_gettext(y->fl, &t, y->lstfile);
	if (errcode < 0)
		goto error;

	errcode = parse_yasm_labels(y->l, t);
	if (errcode < 0)
		goto error;

error:
	return errcode;
}

void yasm_free(struct yasm *y)
{
	if (!y)
		return;

	free(y->fileroot);
	free(y->pttfile);
	free(y->lstfile);
	free(y->binfile);
	fl_free(y->fl);
	st_free(y->st_asm);
	l_free(y->l);
	free(y);
}

int yasm_lookup_label(const struct yasm *y, uint64_t *addr,
		      const char *labelname)
{
	if (bug_on(!y))
		return -err_internal;


	return l_lookup(y->l, addr, labelname);
}

static int yasm_advance_next_line(struct yasm *y)
{
	char s[1024];
	char filename[FILENAME_MAX];
	int errcode;
	int asm_line, asm_inc;

	if (bug_on(!y))
		return -err_internal;


	for (;;) {
		errcode = fl_getline(y->fl, s, sizeof(s), y->lstfile,
				     (size_t) y->lst_curr_line);
		/* always advance in lst file.  */
		y->lst_curr_line += 1;

		if (errcode < 0)
			break;

		/* if the current lst file line is a line directive, set
		 * state information to this file, line and increment
		 * and continue.
		 */
		if (sscanf(s, "%*d %%line %d+%d %1023[^\r\n]", &asm_line,
			   &asm_inc, filename) == 3) {
			st_set_file(y->st_asm, filename, asm_line, asm_inc);
			continue;
		}

		/* if line number or increment in the previous line
		 * directive is <= 0, the current lst line has no
		 * corresponding line in the source file.
		 */
		if (y->st_asm->n <= 0 || y->st_asm->inc <= 0)
			continue;

		/* finally the current line in the lst file can be
		 * correlated to the source file, so we retrieve the
		 * line from it and update the state.
		 */
		errcode = fl_getline(y->fl, s, (size_t) sizeof(s),
				     y->st_asm->filename,
				     (size_t) y->st_asm->n - 1u);
		if (errcode < 0)
			break;

		errcode = st_update(y->st_asm, s);
		break;
	}

	return errcode;
}

int yasm_pd_parse(struct yasm *y, struct pt_directive *pd)
{
	return pd_parse(pd, y->st_asm);
}

int yasm_next_pt_directive(struct yasm *y, struct pt_directive *pd)
{
	int errcode;

	for (;;) {
		errcode = yasm_advance_next_line(y);
		if (errcode < 0)
			break;

		errcode = pd_parse(pd, y->st_asm);
		if (errcode != -err_no_directive)
			return errcode;

	}
	if (errcode == -err_out_of_range)
		errcode = -err_no_directive;

	return errcode;
}

int yasm_next_line(struct yasm *y, char *dest, size_t destlen)
{
	int errcode;

	if (!destlen)
		return 0;

	if (bug_on(!dest))
		return -err_internal;

	errcode = yasm_advance_next_line(y);
	if (errcode < 0)
		return errcode;

	strncpy(dest, y->st_asm->line, destlen);
	dest[destlen-1] = '\0';

	return 0;
}

int yasm_print_err(const struct yasm *y, const char *s, int errcode)
{
	if (bug_on(!y))
		return -err_internal;


	return st_print_err(y->st_asm, s, errcode);
}

int yasm_lookup_section_label(const struct yasm *y, const char *name,
			      const char *attribute, uint64_t *value)
{
	if (bug_on(!y))
		return -err_internal;

	return lookup_section_label(y->l, name, attribute, value);
}
