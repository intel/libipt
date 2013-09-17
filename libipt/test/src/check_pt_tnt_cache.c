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

#include "pt_tnt_cache.h"

#include "pt_error.h"
#include "pt_packet.h"

#include "suites.h"
#include "pt_check.h"

#include <string.h>
#include <check.h>


START_TEST(check_tnt_cache_init)
{
	struct pt_tnt_cache tnt_cache;

	memset(&tnt_cache, 0xcd, sizeof(tnt_cache));

	pt_tnt_cache_init(&tnt_cache);

	ck_uint64_eq(tnt_cache.tnt, 0ull);
	ck_uint64_eq(tnt_cache.index, 0ull);
}
END_TEST

START_TEST(check_tnt_cache_init_null)
{
	pt_tnt_cache_init(NULL);
}
END_TEST

START_TEST(check_tnt_cache_is_empty_initial)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	pt_tnt_cache_init(&tnt_cache);

	status = pt_tnt_cache_is_empty(&tnt_cache);
	ck_int_eq(status, 1);
}
END_TEST

START_TEST(check_tnt_cache_is_empty_no)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	tnt_cache.index = 1ull;

	status = pt_tnt_cache_is_empty(&tnt_cache);
	ck_int_eq(status, 0);
}
END_TEST

START_TEST(check_tnt_cache_is_empty_yes)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	tnt_cache.index = 0ull;

	status = pt_tnt_cache_is_empty(&tnt_cache);
	ck_int_eq(status, 1);
}
END_TEST

START_TEST(check_tnt_cache_is_empty_null)
{
	int status;

	status = pt_tnt_cache_is_empty(NULL);
	ck_int_eq(status, -pte_invalid);
}
END_TEST

START_TEST(check_tnt_cache_query_taken)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	tnt_cache.tnt = 1ull;
	tnt_cache.index = 1ull;

	status = pt_tnt_cache_query(&tnt_cache);
	ck_int_eq(status, 1);
	ck_uint64_eq(tnt_cache.index, 0);
}
END_TEST

START_TEST(check_tnt_cache_query_not_taken)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	tnt_cache.tnt = 0ull;
	tnt_cache.index = 1ull;

	status = pt_tnt_cache_query(&tnt_cache);
	ck_int_eq(status, 0);
	ck_uint64_eq(tnt_cache.index, 0);
}
END_TEST

START_TEST(check_tnt_cache_query_empty)
{
	struct pt_tnt_cache tnt_cache;
	int status;

	tnt_cache.index = 0ull;

	status = pt_tnt_cache_query(&tnt_cache);
	ck_int_eq(status, -pte_bad_query);
}
END_TEST

START_TEST(check_tnt_cache_query_null)
{
	int status;

	status = pt_tnt_cache_query(NULL);
	ck_int_eq(status, -pte_invalid);
}
END_TEST

START_TEST(check_tnt_cache_update_tnt)
{
	struct pt_tnt_cache tnt_cache;
	struct pt_packet_tnt packet;
	int errcode;

	pt_tnt_cache_init(&tnt_cache);

	packet.bit_size = 4ull;
	packet.payload = 8ull;

	errcode = pt_tnt_cache_update_tnt(&tnt_cache, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(tnt_cache.tnt, 8ull);
	ck_uint64_eq(tnt_cache.index, 1ull << 3);
}
END_TEST

START_TEST(check_tnt_cache_update_tnt_not_empty)
{
	struct pt_tnt_cache tnt_cache;
	struct pt_packet_tnt packet;
	int errcode;

	tnt_cache.tnt = 42ull;
	tnt_cache.index = 12ull;

	errcode = pt_tnt_cache_update_tnt(&tnt_cache, &packet, NULL);
	ck_int_eq(errcode, -pte_bad_context);
	ck_uint64_eq(tnt_cache.tnt, 42ull);
	ck_uint64_eq(tnt_cache.index, 12ull);
}
END_TEST

START_TEST(check_tnt_cache_update_tnt_null_tnt)
{
	struct pt_packet_tnt packet;
	int errcode;

	errcode = pt_tnt_cache_update_tnt(NULL, &packet, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_tnt_cache_update_tnt_null_packet)
{
	struct pt_tnt_cache tnt_cache;
	int errcode;

	tnt_cache.tnt = 42ull;
	tnt_cache.index = 12ull;

	errcode = pt_tnt_cache_update_tnt(&tnt_cache, NULL, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_uint64_eq(tnt_cache.tnt, 42ull);
	ck_uint64_eq(tnt_cache.index, 12ull);
}
END_TEST

Suite *suite_pt_tnt_cache(void)
{
	TCase *init, *is_empty, *query, *update_tnt;
	Suite *suite;

	init = tcase_create("init");
	tcase_add_test(init, check_tnt_cache_init);
	tcase_add_test(init, check_tnt_cache_init_null);

	is_empty = tcase_create("is-empty");
	tcase_add_test(init, check_tnt_cache_is_empty_initial);
	tcase_add_test(init, check_tnt_cache_is_empty_no);
	tcase_add_test(init, check_tnt_cache_is_empty_yes);
	tcase_add_test(init, check_tnt_cache_is_empty_null);

	query = tcase_create("query");
	tcase_add_test(init, check_tnt_cache_query_taken);
	tcase_add_test(init, check_tnt_cache_query_not_taken);
	tcase_add_test(init, check_tnt_cache_query_empty);
	tcase_add_test(init, check_tnt_cache_query_null);

	update_tnt = tcase_create("update-tnt");
	tcase_add_test(init, check_tnt_cache_update_tnt);
	tcase_add_test(init, check_tnt_cache_update_tnt_not_empty);
	tcase_add_test(init, check_tnt_cache_update_tnt_null_tnt);
	tcase_add_test(init, check_tnt_cache_update_tnt_null_packet);

	suite = suite_create("tnt-cache");
	suite_add_tcase(suite, init);
	suite_add_tcase(suite, is_empty);
	suite_add_tcase(suite, query);
	suite_add_tcase(suite, update_tnt);

	return suite;
}
