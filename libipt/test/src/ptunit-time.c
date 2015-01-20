/*
 * Copyright (c) 2014-2015, Intel Corporation
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

#include "pt_time.h"

#include "intel-pt.h"

#include "ptunit.h"


/* A time unit test fixture. */

struct time_fixture {
	/* The configuration to use. */
	struct pt_config config;

	/* The time struct to update. */
	struct pt_time time;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct time_fixture *);
	struct ptunit_result (*fini)(struct time_fixture *);
};

static struct ptunit_result tfix_init(struct time_fixture *tfix)
{
	pt_time_init(&tfix->time);

	return ptu_passed();
}


static struct ptunit_result tsc_null(struct time_fixture *tfix)
{
	struct pt_packet_tsc packet;
	int errcode;

	errcode = pt_time_update_tsc(NULL, &packet, &tfix->config);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_time_update_tsc(&tfix->time, NULL, &tfix->config);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result cbr_null(struct time_fixture *tfix)
{
	struct pt_packet_cbr packet;
	int errcode;

	errcode = pt_time_update_cbr(NULL, &packet, &tfix->config);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_time_update_cbr(&tfix->time, NULL, &tfix->config);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result query_tsc_null(struct time_fixture *tfix)
{
	uint64_t tsc;
	int errcode;

	errcode = pt_time_query_tsc(NULL, &tfix->time);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_time_query_tsc(&tsc, NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result query_tsc_none(struct time_fixture *tfix)
{
	uint64_t tsc;
	int errcode;

	errcode = pt_time_query_tsc(&tsc, &tfix->time);
	ptu_int_eq(errcode, -pte_no_time);

	return ptu_passed();
}

static struct ptunit_result query_cbr_null(struct time_fixture *tfix)
{
	uint32_t cbr;
	int errcode;

	errcode = pt_time_query_cbr(NULL, &tfix->time);
	ptu_int_eq(errcode, -pte_internal);

	errcode = pt_time_query_cbr(&cbr, NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result query_cbr_none(struct time_fixture *tfix)
{
	uint32_t cbr;
	int errcode;

	errcode = pt_time_query_cbr(&cbr, &tfix->time);
	ptu_int_eq(errcode, -pte_no_cbr);

	return ptu_passed();
}

static struct ptunit_result tsc(struct time_fixture *tfix)
{
	struct pt_packet_tsc packet;
	uint64_t tsc;
	int errcode;

	packet.tsc = 0xdedededeull;

	errcode = pt_time_update_tsc(&tfix->time, &packet, &tfix->config);
	ptu_int_eq(errcode, 0);

	errcode = pt_time_query_tsc(&tsc, &tfix->time);
	ptu_int_eq(errcode, 0);

	ptu_uint_eq(tsc, 0xdedededeull);

	return ptu_passed();
}

static struct ptunit_result cbr(struct time_fixture *tfix)
{
	struct pt_packet_cbr packet;
	uint32_t cbr;
	int errcode;

	packet.ratio = 0x38;

	errcode = pt_time_update_cbr(&tfix->time, &packet, &tfix->config);
	ptu_int_eq(errcode, 0);

	errcode = pt_time_query_cbr(&cbr, &tfix->time);
	ptu_int_eq(errcode, 0);

	ptu_uint_eq(cbr, 0x38);

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct ptunit_suite suite;
	struct time_fixture tfix;

	suite = ptunit_mk_suite(argc, argv);

	tfix.init = tfix_init;
	tfix.fini = NULL;

	ptu_run_f(suite, tsc_null, tfix);
	ptu_run_f(suite, cbr_null, tfix);

	ptu_run_f(suite, query_tsc_null, tfix);
	ptu_run_f(suite, query_tsc_none, tfix);
	ptu_run_f(suite, query_cbr_null, tfix);
	ptu_run_f(suite, query_cbr_none, tfix);

	ptu_run_f(suite, tsc, tfix);
	ptu_run_f(suite, cbr, tfix);

	ptunit_report(&suite);
	return suite.nr_fails;
}
