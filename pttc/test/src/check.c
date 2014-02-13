/*
 * Copyright (c) 2013-2014, Intel Corporation
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
#include "parse.h"
#include "pttc.h"
#include "util.h"
#include "yasm.h"

#include <check.h>
#include <stdio.h>

/* Adds a test case to the given suite.  */
void _add_to_suite(Suite *suite, const char *name, TFun f)
{
	TCase *tc;

	tc = tcase_create(name);
	tcase_add_test(tc, f);
	suite_add_tcase(suite, tc);

}
/* Adds a test case to the given suite and use the test case function as
 * test case name.  */
#define add_to_suite(suite, f) _add_to_suite(suite, #f, f)

/* Checks if all error codes have a string function.  */
START_TEST(check_errcode_enum)
{
	ck_assert_str_eq("success", errstr[success]);

	ck_assert_str_eq("cannot open file", errstr[err_file_open]);
	ck_assert_str_eq("cannot read file", errstr[err_file_read]);
	ck_assert_str_eq("cannot get file size", errstr[err_file_size]);
	ck_assert_str_eq("cannot write file", errstr[err_file_write]);
	ck_assert_str_eq("out of range", errstr[err_out_of_range]);

	ck_assert_str_eq("label has no address", errstr[err_label_addr]);
	ck_assert_str_eq("yasm directive 'section' is not supported",
			 errstr[err_section]);
	ck_assert_str_eq("no pt directive", errstr[err_no_directive]);
	ck_assert_str_eq("no such label", errstr[err_no_label]);

	ck_assert_str_eq("missing ')'", errstr[err_missing_closepar]);
	ck_assert_str_eq("missing '('", errstr[err_missing_openpar]);

	ck_assert_str_eq("parse error", errstr[err_parse]);
	ck_assert_str_eq("integer cannot be parsed", errstr[err_parse_int]);
	ck_assert_str_eq("integer too big", errstr[err_parse_int_too_big]);
	ck_assert_str_eq("ip missing", errstr[err_parse_ip_missing]);
	ck_assert_str_eq("no arguments", errstr[err_parse_no_args]);
	ck_assert_str_eq("trailing tokens", errstr[err_parse_trailing_tokens]);
	ck_assert_str_eq("unknown character", errstr[err_parse_unknown_char]);
	ck_assert_str_eq("unknown directive",
			 errstr[err_parse_unknown_directive]);
	ck_assert_str_eq("missing directive",
			 errstr[err_parse_missing_directive]);

	ck_assert_str_eq("pt library error", errstr[err_pt_lib]);

	ck_assert_str_eq("run failed", errstr[err_run]);

	ck_assert_str_eq("unspecified error", errstr[err_other]);

	ck_assert_str_eq("out of memory", errstr[err_no_mem]);

	ck_assert_str_eq("internal error", errstr[err_internal]);

	ck_assert_str_eq("processing stopped", errstr[stop_process]);

	ck_assert_str_eq("max error code", errstr[err_max]);
}
END_TEST


/* Checks if parse_tnt works.  */
START_TEST(check_parse_tnt)
{
	struct test {
		int valid;
		const char *payload;
		uint64_t tnt;
		uint8_t size;
	};
	struct test tests[] = {
		/* Valid input.  */
		{1, "", 0x00, 0},
		{1, "n", 0x00, 1},
		{1, "t", 0x01, 1},
		{1, "nn", 0x00, 2},
		{1, "nt", 0x01, 2},
		{1, "tn", 0x02, 2},
		{1, "tt", 0x03, 2},
		{1, "tttttttt", 0xff, 8},
		{1, "nnnnnnnn", 0x00, 8},
		{1, "t.t.t.t.t.t.t.t", 0xff, 8},
		{1, "n n n n n n n n", 0x00, 8},

		/* Invalid input.  */
		{0, "a b c", 0x00, 0},
		{0, "n t m t", 0x00, 0},
	};

	for (size_t i = 0; i < sizeof(tests)/sizeof(struct test); i++) {
		enum errcode errcode;
		uint64_t tnt = 31337;
		uint8_t size = -1;
		char *payload;

		payload = duplicate_str(tests[i].payload);
		ck_assert(!!payload);

		errcode = parse_tnt(&tnt, &size, payload);
		if (tests[i].valid) {
			ck_assert_msg(errcode == 0, tests[i].payload);
			ck_assert_msg(tests[i].tnt == tnt, tests[i].payload);
			ck_assert_msg(tests[i].size == size, tests[i].payload);
		} else {
			ck_assert_msg(errcode != 0, tests[i].payload);
		}

		free(payload);
	}
}
END_TEST


/* Checks if parse_ip works.  */
START_TEST(check_parse_ip)
{
	struct test {
		int valid;
		const char *payload;
		uint64_t ip;
		size_t size;
	};
	struct test tests[] = {
		/* no prefix.  */
		{1, "1: 0", 0, 1},
		{1, "2: 1", 1, 2},
		{1, "3: 281474976710655", 281474976710655, 3},

		/* hex prefix.  */
		{1, "1: 0x0", 0, 1},
		{1, "2: 0x1", 1, 2},
		{1, "3: 0x01", 1, 3},
		{1, "3: 0xffffffffffff", 0xffffffffffff, 3},

		/* octal prefix.  */
		{1, "1: 00", 0, 1},
		{1, "1: 01", 1, 1},
		{1, "1: 010", 010, 1},
		{1, "3: 07777777777777777", 07777777777777777, 3},

		/* too big, but no error generated  */
		{1, "3: 0x1000000000000", 0x1000000000000, 3},
		{1, "2: 0x1000000000000", 0x1000000000000, 2},
		{1, "1: 0x100", 0x100, 1},
		{1, "0: 0x100", 0x100, 0},

		/* invalid characters.  */
		{0, "13e", 0, 0},
		{0, "abc", 0, 0},
		{0, "abc: 0", 0, 0},
		{0, "13e: 0", 0, 0},

		/* invalid size.  */
		{0, "-1: 0", 0, 0},
		{0, "4: 0", 0, 0},

		/* missing size.  */
		{0, ":0", 0, 0},
		{0, ":0x100", 0, 0},
		{0, ":0777", 0, 0},
	};

	for (size_t i = 0; i < sizeof(tests)/sizeof(struct test); i++) {
		enum errcode errcode;
		uint64_t ip;
		enum pt_ip_compression size;
		char *payload;

		payload = duplicate_str(tests[i].payload);
		ck_assert(!!payload);

		errcode = parse_ip(NULL, &ip, &size, payload);
		if (tests[i].valid) {
			ck_assert_msg(errcode == 0, tests[i].payload);
			ck_assert_msg(tests[i].ip == ip, tests[i].payload);
			ck_assert_msg(tests[i].size == size, tests[i].payload);
		} else {
			ck_assert_msg(errcode != 0, tests[i].payload);
		}

		free(payload);
	}
}
END_TEST

/* Checks if parse_uint64 works.  */
START_TEST(check_parse_uint64)
{
	struct test {
		int valid;
		const char *payload;
		uint64_t x;
	};
	struct test tests[] = {
		/* Valid input.  */
		{1, "0", 0},
		{1, "0xffff", 0xffff},
		{1, ", 12, u", 12},

		/* Invalid input.  */
		{0, "", 0},
		{0, ", ", 0},
		{0, "12k", 0},
	};

	for (size_t i = 0; i < sizeof(tests)/sizeof(struct test); i++) {
		enum errcode errcode;
		uint64_t x = 31337;
		char *payload;

		payload = duplicate_str(tests[i].payload);
		ck_assert(!!payload);

		errcode = parse_uint64(&x, payload);
		if (tests[i].valid) {
			ck_assert_msg(errcode == 0, tests[i].payload);
			ck_assert_msg(tests[i].x == x, tests[i].payload);
		} else {
			ck_assert_msg(errcode != 0, tests[i].payload);
		}

		free(payload);
	}
}
END_TEST

const char *FILE_EMPTY = "";
const char *FILE_MIXED =
	"lin\re1\n"
	"lin\re2\r\n"
	"line3\r";
const char *FILE_NL_DEFAULT =
	"line1\n"
	"line2\n"
	"line3\n";
const char *FILE_NL_NOEOL =
	"line1\n"
	"line2\n"
	"line3";
const char *FILE_CRNL_DEFAULT =
	"line1\r\n"
	"line2\r\n"
	"line3\r\n";
const char *FILE_CRNL_NOEOL =
	"line1\r\n"
	"line2\r\n"
	"line3";
const char *FILE_CRNL_NOEOL_CR_ONLY =
	"line1\r\n"
	"line2\r\n"
	"line3\r";

START_TEST(check_file_all)
{
	struct test {
		const char *text;
		char *filename;
	};
	struct test tests[] = {
		{FILE_EMPTY, ""},
		{FILE_MIXED, ""},
		{FILE_NL_DEFAULT, ""},
		{FILE_NL_NOEOL, ""},
		{FILE_CRNL_DEFAULT, ""},
		{FILE_CRNL_NOEOL, ""},
		{FILE_CRNL_NOEOL_CR_ONLY, ""},
	};
	struct file_list *fl;
	size_t i;

	fl = fl_alloc();
	ck_assert(!!fl);

	for (i = 0; i < sizeof(tests)/sizeof(struct test); i++) {
		int errcode;
		char *filename;
		FILE *f;
		size_t n;
		const size_t ll = 10;
		char l[ll];

		filename = tmpnam(NULL);

		/* filename should not exist, so it cannot be opened.  */
		ck_assert(fl_getline(fl, l, ll, filename, 0) != 0);

		/* save test text in file named filename.  */
		f = fopen(filename, "w");
		ck_assert(f != NULL);
		n = strlen(tests[i].text);
		ck_assert(fwrite(tests[i].text, sizeof(char), n, f) == n);
		fclose(f);

		/* filename exists and should be cached.  */
		errcode = fl_getline(fl, l, ll, filename, 0);
		ck_assert((i == 0 && errcode != 0) || (i != 0 && errcode == 0));
		remove(filename);

		/* test edges.  */
		ck_assert(fl_getline(fl, l, ll, filename, -1) != 0);
		ck_assert(fl_getline(fl, l, ll, filename, 3) != 0);
		switch (i) {
		case 0:
			/* empty file means no lines at all.  */
			errcode = fl_getline(fl, l, ll, filename, 0);
			ck_assert(errcode == -err_out_of_range);
			break;
		case 1:
			ck_assert(fl_getline(fl, l, ll, filename, 0) == 0);
			ck_assert(strcmp(l, "lin\re1") == 0);
			ck_assert(fl_getline(fl, l, ll, filename, 1) == 0);
			ck_assert(strcmp(l, "lin\re2") == 0);
			ck_assert(fl_getline(fl, l, ll, filename, 2) == 0);
			ck_assert(strcmp(l, "line3") == 0);
			break;
		default:
			ck_assert(fl_getline(fl, l, ll, filename, 0) == 0);
			ck_assert(strcmp(l, "line1") == 0);
			ck_assert(fl_getline(fl, l, ll, filename, 1) == 0);
			ck_assert(strcmp(l, "line2") == 0);
			ck_assert(fl_getline(fl, l, ll, filename, 2) == 0);
			ck_assert(strcmp(l, "line3") == 0);
		}
	}

	fl_free(fl);
}
END_TEST

const char *test_yasm_lstfile =
	"     1""                                 ""%line 1+1 tests/test1.asm\n"
	"     2""                                 ""[bits 64]\n"
	"     3""                                 ""[org 0x1000]\n"
	"     4""                                 ""\n"
	"     5""                                 ""\n"
	"     6""                                 ""\n"
	"     7""                                 ""\n"
	"     8"" 00000000 B904000000             ""mov ecx, 1\n"
	"     9"" 00000005 B904000000             ""mov ecx, 2\n"
	"    10"" 0000000A B904000000             ""mov ecx, 4\n"
	"    11"" 0000000F EBFE                   ""jmp l1\n"
	"    12""                                 ""\n"
	"    13"" 00000011 B904000000             ""l1: mov ecx, 5\n"
	"    14""                                 ""l2:\n"
	"    15""                                 ""\n"
	"    16"" 00000016 B904000000             ""mov ecx, 6\n";

START_TEST(check_yasm_label)
{
	int errcode;
	struct text *t;
	struct label *l;
	uint64_t addr;

	t = text_alloc(test_yasm_lstfile);
	ck_assert(!!t);

	l = l_alloc();
	ck_assert(!!l);

	errcode = parse_yasm_labels(l, t);
	ck_assert(errcode == 0);

	errcode = l_lookup(l, &addr, "l1");
	ck_assert(errcode == 0);
	ck_assert(addr == 0x1000 + 0x11);

	errcode = l_lookup(l, &addr, "l2");
	ck_assert(errcode == 0);
	ck_assert(addr == 0x1000 + 0x16);

	errcode = l_lookup(l, &addr, "does_not_exist");
	ck_assert(errcode == -err_no_label);
	ck_assert(addr == 0);

	l_free(l);
	text_free(t);
}
END_TEST

START_TEST(check_util_run_echo)
{
	int errcode;
	char *const argv[] = {
		"echo", "hello", "world", NULL,
	};

	errcode = run(argv[0], argv);
	ck_assert(errcode == 0);
}
END_TEST

START_TEST(check_util_run_false)
{
	int errcode;
	char *const argv[] = {
		"false", NULL,
	};

	errcode = run(argv[0], argv);
	ck_assert(errcode == -err_run);
}
END_TEST

START_TEST(check_util_run_nexist)
{
	int errcode;
	char *const argv[] = {
		"does_not_exist", NULL,
	};

	errcode = run(argv[0], argv);
	ck_assert(errcode == -err_run);
}
END_TEST

Suite *suite_errcode(void)
{
	Suite *suite;

	suite = suite_create("errcode");
	add_to_suite(suite, check_errcode_enum);

	return suite;
}

Suite *suite_parse(void)
{
	Suite *suite;

	suite = suite_create("parse");
	add_to_suite(suite, check_parse_tnt);
	add_to_suite(suite, check_parse_ip);
	add_to_suite(suite, check_parse_uint64);

	return suite;
}

Suite *suite_util(void)
{
	Suite *suite;

	suite = suite_create("util");
	add_to_suite(suite, check_util_run_echo);
	add_to_suite(suite, check_util_run_false);
	add_to_suite(suite, check_util_run_nexist);

	return suite;
}

Suite *suite_file(void)
{
	Suite *suite;

	suite = suite_create("file");
	add_to_suite(suite, check_file_all);

	return suite;
}

Suite *suite_yasm(void)
{
	Suite *suite;

	suite = suite_create("yasm");
	add_to_suite(suite, check_yasm_label);

	return suite;
}

int main(void)
{
	int ntests_failed;

	SRunner *srunner = srunner_create(NULL);

	srunner_add_suite(srunner, suite_errcode());
	srunner_add_suite(srunner, suite_file());
	srunner_add_suite(srunner, suite_util());
	srunner_add_suite(srunner, suite_parse());
	srunner_add_suite(srunner, suite_yasm());

	srunner_run_all(srunner, CK_ENV);

	ntests_failed = srunner_ntests_failed(srunner);

	srunner_free(srunner);

	return ntests_failed;
}
