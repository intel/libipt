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

#include "pt_last_ip.h"

#include "pt_error.h"
#include "pt_packet.h"

#include "suites.h"
#include "pt_check.h"

#include <string.h>
#include <check.h>


START_TEST(check_last_ip_init)
{
	struct pt_last_ip last_ip;

	memset(&last_ip, 0xcd, sizeof(last_ip));

	pt_last_ip_init(&last_ip);

	ck_uint64_eq(last_ip.ip, 0ull);
	ck_uint_eq(last_ip.need_full_ip, 1);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_init_null)
{
	pt_last_ip_init(NULL);
}
END_TEST

START_TEST(check_last_ip_status_initial)
{
	struct pt_last_ip last_ip;
	int errcode;

	pt_last_ip_init(&last_ip);

	errcode = pt_last_ip_query(NULL, &last_ip);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_last_ip_status)
{
	struct pt_last_ip last_ip;
	int errcode;

	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	errcode = pt_last_ip_query(NULL, &last_ip);
	ck_int_eq(errcode, 0);
}
END_TEST

START_TEST(check_last_ip_status_null)
{
	int errcode;

	errcode = pt_last_ip_query(NULL, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_last_ip_status_noip)
{
	struct pt_last_ip last_ip;
	int errcode;

	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	errcode = pt_last_ip_query(NULL, &last_ip);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_last_ip_status_suppressed)
{
	struct pt_last_ip last_ip;
	int errcode;

	last_ip.need_full_ip = 0;
	last_ip.suppressed = 1;

	errcode = pt_last_ip_query(NULL, &last_ip);
	ck_int_eq(errcode, -pte_ip_suppressed);
}
END_TEST

START_TEST(check_last_ip_query_initial)
{
	struct pt_last_ip last_ip;
	uint64_t ip;
	int errcode;

	pt_last_ip_init(&last_ip);

	errcode = pt_last_ip_query(&ip, &last_ip);
	ck_int_eq(errcode, -pte_noip);
}
END_TEST

START_TEST(check_last_ip_query)
{
	struct pt_last_ip last_ip;
	uint64_t ip, exp = 42ull;
	int errcode;

	last_ip.ip = 42ull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	errcode = pt_last_ip_query(&ip, &last_ip);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, exp);
}
END_TEST

START_TEST(check_last_ip_query_null)
{
	uint64_t ip = 13ull;
	int errcode;

	errcode = pt_last_ip_query(&ip, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_uint64_eq(ip, 13ull);
}
END_TEST

START_TEST(check_last_ip_query_noip)
{
	struct pt_last_ip last_ip;
	uint64_t ip = 13ull;
	int errcode;

	last_ip.ip = 42ull;
	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	errcode = pt_last_ip_query(&ip, &last_ip);
	ck_int_eq(errcode, -pte_noip);
	ck_uint64_eq(ip, 0ull);
}
END_TEST

START_TEST(check_last_ip_query_suppressed)
{
	struct pt_last_ip last_ip;
	uint64_t ip = 13ull;
	int errcode;

	last_ip.ip = 42ull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 1;

	errcode = pt_last_ip_query(&ip, &last_ip);
	ck_int_eq(errcode, -pte_ip_suppressed);
	ck_uint64_eq(ip, 0ull);
}
END_TEST

START_TEST(check_last_ip_update_ip_suppressed)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 42ull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_suppressed;
	packet.ip = 13ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 42ull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 1);
}
END_TEST

START_TEST(check_last_ip_update_ip_upd16)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0xff0042ull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccc013ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 0xffc013ull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_upd32)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0xff00000420ull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcc0000c013ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 0xff0000c013ull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_sext48)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0x7fffffffffffffffull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xff00000000ffull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 0xffffff00000000ffull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_suppressed_noip)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 42ull;
	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_suppressed;
	packet.ip = 13ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 42ull);
	ck_uint_eq(last_ip.need_full_ip, 1);
	ck_uint_eq(last_ip.suppressed, 1);
}
END_TEST

START_TEST(check_last_ip_update_ip_upd16_noip)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0xff0042ull;
	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_update_16;
	packet.ip = 0xccc013ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, -pte_noip);
	ck_uint64_eq(last_ip.ip, 0xff0042ull);
	ck_uint_eq(last_ip.need_full_ip, 1);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_upd32_noip)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0xff00000420ull;
	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_update_32;
	packet.ip = 0xcc0000c013ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, -pte_noip);
	ck_uint64_eq(last_ip.ip, 0xff00000420ull);
	ck_uint_eq(last_ip.need_full_ip, 1);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_sext48_noip)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0x7fffffffffffffffull;
	last_ip.need_full_ip = 1;
	last_ip.suppressed = 0;

	packet.ipc = pt_ipc_sext_48;
	packet.ip = 0xff00000000ffull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, 0);
	ck_uint64_eq(last_ip.ip, 0xffffff00000000ffull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_bad_packet)
{
	struct pt_last_ip last_ip;
	struct pt_packet_ip packet;
	int errcode;

	last_ip.ip = 0x7fffffffffffffffull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	packet.ipc = (enum pt_ip_compression) 0xff;
	packet.ip = 0ull;

	errcode = pt_last_ip_update_ip(&last_ip, &packet, NULL);
	ck_int_eq(errcode, -pte_bad_packet);
	ck_uint64_eq(last_ip.ip, 0x7fffffffffffffffull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

START_TEST(check_last_ip_update_ip_null_ip)
{
	struct pt_packet_ip packet;
	int errcode;

	errcode = pt_last_ip_update_ip(NULL, &packet, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_last_ip_update_ip_null_packet)
{
	struct pt_last_ip last_ip;
	int errcode;

	last_ip.ip = 0x7fffffffffffffffull;
	last_ip.need_full_ip = 0;
	last_ip.suppressed = 0;

	errcode = pt_last_ip_update_ip(&last_ip, NULL, NULL);
	ck_int_eq(errcode, -pte_invalid);
	ck_uint64_eq(last_ip.ip, 0x7fffffffffffffffull);
	ck_uint_eq(last_ip.need_full_ip, 0);
	ck_uint_eq(last_ip.suppressed, 0);
}
END_TEST

Suite *suite_pt_last_ip(void)
{
	TCase *init, *status, *query, *update_ip;
	Suite *suite;

	init = tcase_create("init");
	tcase_add_test(init, check_last_ip_init);
	tcase_add_test(init, check_last_ip_init_null);

	status = tcase_create("status");
	tcase_add_test(status, check_last_ip_status_initial);
	tcase_add_test(status, check_last_ip_status);
	tcase_add_test(status, check_last_ip_status_null);
	tcase_add_test(status, check_last_ip_status_noip);
	tcase_add_test(status, check_last_ip_status_suppressed);

	query = tcase_create("query");
	tcase_add_test(query, check_last_ip_query_initial);
	tcase_add_test(query, check_last_ip_query);
	tcase_add_test(query, check_last_ip_query_null);
	tcase_add_test(query, check_last_ip_query_noip);
	tcase_add_test(query, check_last_ip_query_suppressed);

	update_ip = tcase_create("update-ip");
	tcase_add_test(update_ip, check_last_ip_update_ip_suppressed);
	tcase_add_test(update_ip, check_last_ip_update_ip_upd16);
	tcase_add_test(update_ip, check_last_ip_update_ip_upd32);
	tcase_add_test(update_ip, check_last_ip_update_ip_sext48);
	tcase_add_test(update_ip, check_last_ip_update_ip_suppressed_noip);
	tcase_add_test(update_ip, check_last_ip_update_ip_upd16_noip);
	tcase_add_test(update_ip, check_last_ip_update_ip_upd32_noip);
	tcase_add_test(update_ip, check_last_ip_update_ip_sext48_noip);
	tcase_add_test(update_ip, check_last_ip_update_ip_bad_packet);
	tcase_add_test(update_ip, check_last_ip_update_ip_null_ip);
	tcase_add_test(update_ip, check_last_ip_update_ip_null_packet);

	suite = suite_create("last-ip");
	suite_add_tcase(suite, init);
	suite_add_tcase(suite, query);
	suite_add_tcase(suite, status);
	suite_add_tcase(suite, update_ip);

	return suite;
}
