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

#include "pt_packet.h"

#include "pt_decoder_fixture.h"
#include "suites.h"

#include "pt_packet.h"
#include "pt_error.h"

#include <check.h>


START_TEST(check_packet_null_packet_fail)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	int errcode;

	errcode = pt_decode(NULL, decoder);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_packet_null_decoder_fail)
{
	struct pt_packet packet;
	int errcode;

	errcode = pt_decode(&packet, NULL);
	ck_int_eq(errcode, -pte_invalid);
}
END_TEST

START_TEST(check_packet_psb_plus)
{
	struct pt_decoder_fixture_s *dfix = &pt_decoder_fixture;
	struct pt_decoder *decoder = dfix->decoder;
	struct pt_encoder *encoder = &dfix->encoder;
	struct pt_packet packet;
	uint64_t cr3 = pt_dfix_max_cr3, ip = pt_dfix_max_ip;
	int errcode;

	check_encode_psb(encoder);
	check_encode_mode_exec(encoder, ptem_32bit);
	check_encode_mode_tsx(encoder, pt_mob_tsx_intx);
	check_encode_pip(encoder, cr3);
	check_encode_fup(encoder, ip, pt_ipc_sext_48);
	check_encode_psbend(encoder);

	pt_sync_decoder(decoder);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_psb);
	ck_int_eq(packet.type, ppt_psb);
	ck_uint_eq(packet.size, ptps_psb);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_exec);
	ck_int_eq(packet.payload.mode.bits.exec.csl, 1);
	ck_int_eq(packet.payload.mode.bits.exec.csd, 0);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_mode);
	ck_int_eq(packet.type, ppt_mode);
	ck_uint_eq(packet.size, ptps_mode);
	ck_int_eq(packet.payload.mode.leaf, pt_mol_tsx);
	ck_int_eq(packet.payload.mode.bits.tsx.intx, 1);
	ck_int_eq(packet.payload.mode.bits.tsx.abrt, 0);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_pip);
	ck_int_eq(packet.type, ppt_pip);
	ck_uint_eq(packet.size, ptps_pip);
	ck_int_eq(packet.payload.pip.cr3, cr3);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_fup_sext48);
	ck_int_eq(packet.type, ppt_fup);
	ck_uint_eq(packet.size, ptps_fup_sext48);
	ck_int_eq(packet.payload.ip.ipc, pt_ipc_sext_48);
	ck_int_eq(packet.payload.ip.ip, ip);

	errcode = pt_decode(&packet, decoder);
	ck_int_eq(errcode, ptps_psbend);
	ck_int_eq(packet.type, ppt_psbend);
	ck_uint_eq(packet.size, ptps_psbend);
}
END_TEST

static void add_decode_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_packet_psb_plus);
}

static void add_neg_tests(TCase *tcase)
{
	tcase_add_test(tcase, check_packet_null_packet_fail);
	tcase_add_test(tcase, check_packet_null_decoder_fail);
}

static struct tcase_desc tcase_decode = {
	/* .name = */ "decode",
	/* .add_tests = */ add_decode_tests
};

static struct tcase_desc tcase_neg = {
	/* .name = */ "neg",
	/* .add_tests = */ add_neg_tests
};

Suite *suite_pt_packet(void)
{
	Suite *suite;

	suite = suite_create("packet");

	pt_add_tcase(suite, &tcase_decode, &dfix_standard);
	pt_add_tcase(suite, &tcase_neg, &dfix_standard);

	return suite;
}
