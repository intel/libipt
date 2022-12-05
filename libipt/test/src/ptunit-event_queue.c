/*
 * Copyright (c) 2014-2023, Intel Corporation
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

#include "ptunit.h"

#include "pt_event_queue.h"


/* A test fixture providing an initialized event queue. */
struct evq_fixture {
	/* The event queue. */
	struct pt_event_queue evq;

	/* The test fixture initialization and finalization functions. */
	struct ptunit_result (*init)(struct evq_fixture *);
	struct ptunit_result (*fini)(struct evq_fixture *);
};


static struct ptunit_result efix_init(struct evq_fixture *efix)
{
	pt_evq_init(&efix->evq);

	return ptu_passed();
}

static struct ptunit_result standalone_null(void)
{
	struct pt_event *ev;

	ev = pt_evq_standalone(NULL);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result standalone(struct evq_fixture *efix)
{
	struct pt_event *ev;

	ev = pt_evq_standalone(&efix->evq);
	ptu_ptr(ev);
	ptu_uint_eq(ev->ip_suppressed, 0ul);
	ptu_uint_eq(ev->status_update, 0ul);

	return ptu_passed();
}

static struct ptunit_result enqueue_null(uint32_t evb)
{
	struct pt_event *ev;

	ev = pt_evq_enqueue(NULL, evb);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result dequeue_null(uint32_t evb)
{
	struct pt_event *ev;

	ev = pt_evq_dequeue(NULL, evb);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result requeue_null(struct evq_fixture *efix,
					 uint32_t evb)
{
	struct pt_event *ev, lev;

	ev = pt_evq_requeue(NULL, &lev, evb);
	ptu_null(ev);

	ev = pt_evq_requeue(&efix->evq, NULL, evb);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result dequeue_empty(struct evq_fixture *efix,
					  uint32_t evb)
{
	struct pt_event *ev;

	ev = pt_evq_dequeue(&efix->evq, evb);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result evq_empty(struct evq_fixture *efix, uint32_t evb)
{
	int status;

	status = pt_evq_empty(&efix->evq, evb);
	ptu_int_gt(status, 0);

	status = pt_evq_pending(&efix->evq, evb);
	ptu_int_eq(status, 0);

	return ptu_passed();
}

static struct ptunit_result evq_pending(struct evq_fixture *efix, uint32_t evb)
{
	int status;

	status = pt_evq_empty(&efix->evq, evb);
	ptu_int_eq(status, 0);

	status = pt_evq_pending(&efix->evq, evb);
	ptu_int_gt(status, 0);

	return ptu_passed();
}

static struct ptunit_result enqueue_all_dequeue(struct evq_fixture *efix,
						uint32_t enqb, uint32_t deqb,
						size_t num)
{
	struct pt_event *in[evq_max], *out[evq_max];
	size_t idx;

	ptu_uint_le(num, evq_max);

	for (idx = 0; idx < num; ++idx) {
		in[idx] = pt_evq_enqueue(&efix->evq, enqb);
		ptu_ptr(in[idx]);
	}

	ptu_test(evq_pending, efix, enqb);
	ptu_test(evq_empty, efix, ~enqb);

	for (idx = 0; idx < num; ++idx) {
		out[idx] = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out[idx], in[idx]);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result dequeue_requeue_all(struct evq_fixture *efix,
						uint32_t enqb, uint32_t reqb,
						uint32_t deqb, size_t num)
{
	struct pt_event *in[evq_max], *out[evq_max];
	size_t idx;

	ptu_uint_le(num, evq_max);

	for (idx = 0; idx < num; ++idx) {
		in[idx] = pt_evq_enqueue(&efix->evq, enqb);
		ptu_ptr(in[idx]);
	}

	ptu_test(evq_pending, efix, enqb);
	ptu_test(evq_empty, efix, ~enqb);

	for (idx = 0; idx < num; ++idx) {
		out[idx] = pt_evq_dequeue(&efix->evq, enqb);
		ptu_ptr_eq(out[idx], in[idx]);

		in[idx] = pt_evq_requeue(&efix->evq, out[idx], reqb);
		ptu_ptr(in[idx]);
	}

	ptu_test(evq_pending, efix, reqb);
	ptu_test(evq_empty, efix, ~reqb);

	for (idx = 0; idx < num; ++idx) {
		out[idx] = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out[idx], in[idx]);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result standalone_requeue_all(struct evq_fixture *efix,
						   uint32_t reqb, uint32_t deqb,
						   size_t num)
{
	struct pt_event *in[evq_max], *out[evq_max];
	size_t idx;

	ptu_uint_le(num, evq_max);

	for (idx = 0; idx < num; ++idx) {
		struct pt_event *ev;

		ev = pt_evq_standalone(&efix->evq);
		ptu_ptr(ev);

		in[idx] = pt_evq_requeue(&efix->evq, ev, reqb);
		ptu_ptr(in[idx]);
		ptu_ptr_ne(in[idx], ev);
	}

	ptu_test(evq_pending, efix, reqb);
	ptu_test(evq_empty, efix, ~reqb);

	for (idx = 0; idx < num; ++idx) {
		out[idx] = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out[idx], in[idx]);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result enqueue_one_dequeue(struct evq_fixture *efix,
						uint32_t enqb, uint32_t deqb)
{
	size_t idx;

	for (idx = 0; idx < evq_max * 2; ++idx) {
		struct pt_event *in, *out;

		in = pt_evq_enqueue(&efix->evq, enqb);
		ptu_ptr(in);

		out = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out, in);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result dequeue_requeue_one(struct evq_fixture *efix,
						uint32_t enqb, uint32_t reqb,
						uint32_t deqb)
{
	size_t idx;

	for (idx = 0; idx < evq_max * 2; ++idx) {
		struct pt_event *in, *re, *out;

		in = pt_evq_enqueue(&efix->evq, enqb);
		ptu_ptr(in);
		in->type = ptev_overflow;

		out = pt_evq_dequeue(&efix->evq, enqb);
		ptu_ptr_eq(out, in);
		ptu_int_eq(out->type, ptev_overflow);

		re = pt_evq_requeue(&efix->evq, out, reqb);
		ptu_ptr(re);
		ptu_int_eq(re->type, ptev_overflow);

		out = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out, re);
		ptu_int_eq(out->type, ptev_overflow);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result standalone_requeue_one(struct evq_fixture *efix,
						   uint32_t reqb, uint32_t deqb)
{
	size_t idx;

	for (idx = 0; idx < evq_max * 2; ++idx) {
		struct pt_event *in, *re, *out;

		in = pt_evq_standalone(&efix->evq);
		ptu_ptr(in);
		in->type = ptev_overflow;

		re = pt_evq_requeue(&efix->evq, in, reqb);
		ptu_ptr(re);
		ptu_int_eq(re->type, ptev_overflow);

		out = pt_evq_dequeue(&efix->evq, deqb);
		ptu_ptr_eq(out, re);
		ptu_int_eq(out->type, ptev_overflow);
	}

	ptu_test(evq_empty, efix, deqb);

	return ptu_passed();
}

static struct ptunit_result overflow(struct evq_fixture *efix,
				     uint32_t evb, size_t num)
{
	struct pt_event *in[evq_max], *out[evq_max];
	size_t idx;

	ptu_uint_le(num, evq_max - 2);

	for (idx = 0; idx < (evq_max - 2); ++idx) {
		in[idx] = pt_evq_enqueue(&efix->evq, evb);
		ptu_ptr(in[idx]);
	}

	for (idx = 0; idx < num; ++idx) {
		struct pt_event *ev;

		ev = pt_evq_enqueue(&efix->evq, evb);
		ptu_null(ev);
	}

	for (idx = 0; idx < num; ++idx) {
		struct pt_event *ev, *re;

		ev = pt_evq_standalone(&efix->evq);
		ptu_ptr(ev);

		re = pt_evq_requeue(&efix->evq, ev, evb);
		ptu_null(re);
	}

	for (idx = 0; idx < num; ++idx) {
		out[idx] = pt_evq_dequeue(&efix->evq, evb);
		ptu_ptr_eq(out[idx], in[idx]);
	}

	return ptu_passed();
}

static struct ptunit_result dequeue_requeue_full(struct evq_fixture *efix,
						 uint32_t evb)
{
	struct pt_event *ev;
	size_t idx;

	for (idx = 0; idx < (evq_max - 2); ++idx) {
		ev = pt_evq_enqueue(&efix->evq, evb);
		ptu_ptr(ev);

		ev->type = ptev_overflow;
	}

	ev = pt_evq_dequeue(&efix->evq, evb);
	ptu_ptr(ev);
	ptu_int_eq(ev->type, ptev_overflow);
	ev->type = ptev_exstop;

	ev = pt_evq_requeue(&efix->evq, ev, evb);
	ptu_ptr(ev);
	ptu_int_eq(ev->type, ptev_exstop);

	return ptu_passed();
}

static struct ptunit_result clear_null(void)
{
	int errcode;

	errcode = pt_evq_clear(NULL);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result clear_empty(struct evq_fixture *efix)
{
	int errcode;

	errcode = pt_evq_clear(&efix->evq);
	ptu_int_eq(errcode, 0);

	ptu_test(evq_empty, efix, UINT32_MAX);

	return ptu_passed();
}

static struct ptunit_result clear(struct evq_fixture *efix)
{
	struct pt_event *ev;
	int errcode;

	ev = pt_evq_enqueue(&efix->evq, evb_psbend);
	ptu_ptr(ev);

	ev = pt_evq_enqueue(&efix->evq, evb_tip);
	ptu_ptr(ev);

	ev = pt_evq_enqueue(&efix->evq, evb_fup);
	ptu_ptr(ev);

	ev = pt_evq_enqueue(&efix->evq, evb_exstop);
	ptu_ptr(ev);

	errcode = pt_evq_clear(&efix->evq);
	ptu_int_eq(errcode, 0);

	ptu_test(evq_empty, efix, UINT32_MAX);

	return ptu_passed();
}

static struct ptunit_result empty_null(uint32_t evb)
{
	int errcode;

	errcode = pt_evq_empty(NULL, evb);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result pending_null(uint32_t evb)
{
	int errcode;

	errcode = pt_evq_pending(NULL, evb);
	ptu_int_eq(errcode, -pte_internal);

	return ptu_passed();
}

static struct ptunit_result find_null(uint32_t evb, enum pt_event_type evt)
{
	struct pt_event *ev;

	ev = pt_evq_find(NULL, evb, evt);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result find_empty(struct evq_fixture *efix, uint32_t evb,
				       enum pt_event_type evt)
{
	struct pt_event *ev;

	ev = pt_evq_find(&efix->evq, evb, evt);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result find_none_evb(struct evq_fixture *efix,
					  uint32_t enqb, uint32_t evb)
{
	struct pt_event *ev;

	ev = pt_evq_enqueue(&efix->evq, enqb);
	ptu_ptr(ev);
	ev->type = ptev_overflow;

	ev = pt_evq_find(&efix->evq, evb, ptev_overflow);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result find_none_evt(struct evq_fixture *efix,
					  uint32_t evb)
{
	struct pt_event *ev;

	ev = pt_evq_enqueue(&efix->evq, UINT32_MAX);
	ptu_ptr(ev);
	ev->type = ptev_overflow;

	ev = pt_evq_find(&efix->evq, evb, ptev_paging);
	ptu_null(ev);

	return ptu_passed();
}

static struct ptunit_result find(struct evq_fixture *efix, uint32_t evb)
{
	struct pt_event *ev, *in, *out;

	ev = pt_evq_enqueue(&efix->evq, evb);
	ptu_ptr(ev);
	ev->type = ptev_overflow;

	ev = pt_evq_enqueue(&efix->evq, ~evb);
	ptu_ptr(ev);
	ev->type = ptev_paging;

	in = pt_evq_enqueue(&efix->evq, evb);
	ptu_ptr(in);
	in->type = ptev_paging;

	ev = pt_evq_enqueue(&efix->evq, evb);
	ptu_ptr(ev);
	ev->type = ptev_overflow;

	ev = pt_evq_enqueue(&efix->evq, ~evb);
	ptu_ptr(ev);
	ev->type = ptev_paging;

	out = pt_evq_find(&efix->evq, evb, ptev_paging);
	ptu_ptr_eq(out, in);

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct evq_fixture efix;
	struct ptunit_suite suite;

	efix.init = efix_init;
	efix.fini = NULL;

	suite = ptunit_mk_suite(argc, argv);

	ptu_run(suite, standalone_null);
	ptu_run_f(suite, standalone, efix);

	ptu_run_p(suite, enqueue_null, evb_psbend);
	ptu_run_p(suite, enqueue_null, evb_tip | evb_fup);

	ptu_run_p(suite, dequeue_null, evb_psbend);
	ptu_run_p(suite, dequeue_null, evb_tip | evb_fup);

	ptu_run_fp(suite, requeue_null, efix, evb_psbend);
	ptu_run_fp(suite, requeue_null, efix, evb_tip | evb_fup);

	ptu_run_fp(suite, dequeue_empty, efix, evb_psbend);
	ptu_run_fp(suite, dequeue_empty, efix, evb_tip | evb_fup);

	ptu_run_fp(suite, enqueue_all_dequeue, efix, evb_psbend, evb_psbend, 1);
	ptu_run_fp(suite, enqueue_all_dequeue, efix, evb_tip,
		   evb_tip | evb_fup, 2);
	ptu_run_fp(suite, enqueue_all_dequeue, efix, evb_tip | evb_fup,
		   evb_tip, 1);
	ptu_run_fp(suite, enqueue_all_dequeue, efix, evb_tip | evb_fup,
		   evb_fup, 4);
	ptu_run_fp(suite, enqueue_all_dequeue, efix, evb_tip | evb_fup,
		   evb_fup | evb_exstop, 6);

	ptu_run_fp(suite, dequeue_requeue_all, efix, evb_psbend, evb_psbend,
		   evb_psbend, 1);
	ptu_run_fp(suite, dequeue_requeue_all, efix, evb_tip, evb_fup,
		   evb_fup | evb_psbend, 6);
	ptu_run_fp(suite, dequeue_requeue_all, efix, evb_tip,
		   evb_fup | evb_psbend, evb_fup, 6);

	ptu_run_fp(suite, standalone_requeue_all, efix, evb_psbend,
		   evb_psbend, 1);
	ptu_run_fp(suite, standalone_requeue_all, efix, evb_fup,
		   evb_fup | evb_psbend, 6);
	ptu_run_fp(suite, standalone_requeue_all, efix, evb_fup | evb_tip,
		   evb_tip, 6);

	ptu_run_fp(suite, enqueue_one_dequeue, efix, evb_psbend, evb_psbend);
	ptu_run_fp(suite, enqueue_one_dequeue, efix, evb_tip,
		   evb_tip | evb_fup);
	ptu_run_fp(suite, enqueue_one_dequeue, efix, evb_tip | evb_fup,
		   evb_fup);
	ptu_run_fp(suite, enqueue_one_dequeue, efix, evb_tip | evb_fup,
		   evb_fup | evb_exstop);

	ptu_run_fp(suite, dequeue_requeue_one, efix, evb_fup, evb_fup, evb_fup);
	ptu_run_fp(suite, dequeue_requeue_one, efix, evb_tip | evb_fup,
		   evb_exstop | evb_fup, evb_exstop);

	ptu_run_fp(suite, standalone_requeue_one, efix, evb_fup, evb_fup);
	ptu_run_fp(suite, standalone_requeue_one, efix, evb_tip | evb_fup,
		   evb_exstop | evb_fup);

	ptu_run_fp(suite, overflow, efix, evb_psbend, 1);
	ptu_run_fp(suite, overflow, efix, evb_tip, 2);
	ptu_run_fp(suite, overflow, efix, evb_fup, 3);

	ptu_run_fp(suite, dequeue_requeue_full, efix, evb_psbend);

	ptu_run(suite, clear_null);
	ptu_run_f(suite, clear_empty, efix);
	ptu_run_f(suite, clear, efix);

	ptu_run_p(suite, empty_null, evb_psbend);
	ptu_run_p(suite, empty_null, evb_tip | evb_fup);

	ptu_run_p(suite, pending_null, evb_psbend);
	ptu_run_p(suite, pending_null, evb_tip | evb_fup);

	ptu_run_p(suite, find_null, evb_psbend, ptev_enabled);
	ptu_run_p(suite, find_null, evb_tip | evb_fup, ptev_paging);

	ptu_run_fp(suite, find_empty, efix, evb_psbend, ptev_enabled);
	ptu_run_fp(suite, find_empty, efix, evb_tip | evb_fup, ptev_paging);

	ptu_run_fp(suite, find_none_evb, efix, evb_psbend, evb_tip | evb_fup);
	ptu_run_fp(suite, find_none_evb, efix, evb_tip | evb_fup, evb_exstop);
	ptu_run_fp(suite, find_none_evb, efix, evb_fup, evb_tip);

	ptu_run_fp(suite, find_none_evt, efix, evb_psbend);
	ptu_run_fp(suite, find_none_evt, efix, evb_tip | evb_fup);

	ptu_run_fp(suite, find, efix, evb_psbend);
	ptu_run_fp(suite, find, efix, evb_tip | evb_fup);

	return ptunit_report(&suite);
}
