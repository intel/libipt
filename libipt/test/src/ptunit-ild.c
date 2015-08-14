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

#include "ptunit.h"

#include "pti-ild.h"

#include <string.h>


enum pti_interest {
	pti_interesting = 1,
	pti_boring = 0
};

static const uint64_t pti_addr = 0xffccffccffccull;

/* Check that an instruction
 * - can be length-decoded
 * - is correctly length-decoded
 * - can be classified
 * - is corectly diagnosed as interesting/boring
 *
 * Does not check whether the classification is correct.
 * This is left to the calling test.
 */
static struct ptunit_result ptunit_ild_decode(pti_ild_t *ild,
					      pti_bool_t interest,
					      pti_uint32_t size)
{
	pti_bool_t lret, dret;

	lret = pti_instruction_length_decode(ild);
	ptu_int_eq(lret, 1);
	ptu_uint_eq(ild->length, size);

	dret = pti_instruction_decode(ild);
	ptu_int_eq(dret, interest);

	return ptu_passed();
}

/* Initialize an ILD decoder for testing.
 *
 * We can't use a fixture since we don't know the instruction size upfront.
 */
static void ptunit_ild_init(pti_ild_t *ild, pti_uint8_t *insn,
			    pti_uint32_t size,
			    pti_machine_mode_enum_t mode)
{
	memset(ild, 0, sizeof(*ild));
	ild->itext = insn;
	ild->max_bytes = size;
	ild->mode = mode;
	ild->runtime_address = pti_addr;
}

/* Check that a boring instruction is decoded correctly. */
static struct ptunit_result ptunit_ild_boring(pti_uint8_t *insn,
					      pti_uint32_t size,
					      pti_machine_mode_enum_t mode)
{
	pti_ild_t ild;

	ptunit_ild_init(&ild, insn, size, mode);
	ptu_test(ptunit_ild_decode, &ild, pti_boring, size);

	return ptu_passed();
}

/* Check that an interesting instruction is decoded and classified correctly. */
static struct ptunit_result ptunit_ild_classify(pti_uint8_t *insn,
						pti_uint32_t size,
						pti_machine_mode_enum_t mode,
						pti_inst_enum_t iclass)
{
	pti_ild_t ild;

	ptunit_ild_init(&ild, insn, size, mode);
	ptu_test(ptunit_ild_decode, &ild, pti_interesting, size);
	ptu_int_eq(ild.iclass, iclass);

	return ptu_passed();
}

/* Macros to automatically update the test location. */
#define ptu_boring(insn, size, mode)		\
	ptu_check(ptunit_ild_boring, insn, size, mode)

#define ptu_classify(insn, size, mode, iclass)			\
	ptu_check(ptunit_ild_classify, insn, size, mode, iclass)

/* Macros to also automatically supply the instruction size. */
#define ptu_boring_s(insn, mode)			\
	ptu_boring(insn, sizeof(insn), mode)

#define ptu_classify_s(insn, mode, iclass)		\
	ptu_classify(insn, sizeof(insn), mode, iclass)


static struct ptunit_result push(void)
{
	pti_uint8_t insn[] = { 0x68, 0x11, 0x22, 0x33, 0x44 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result jmp_rel(void)
{
	pti_uint8_t insn[] = { 0xE9, 0x60, 0xF9, 0xFF, 0xFF };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_JMP_E9);

	return ptu_passed();
}

static struct ptunit_result long_nop(void)
{
	pti_uint8_t insn[] = { 0x66, 0x66, 0x66, 0x66,
			       0x66, 0x66, 0X2E, 0X0F,
			       0X1F, 0x84, 0x00, 0x00,
			       0x00, 0x00, 0x00 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result mov_al_64(void)
{
	pti_uint8_t insn[] = { 0x48, 0xA1, 0x3f, 0xaa, 0xbb,
			       0xcc, 0xdd, 0xee, 0xfF,
			       0X11 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result mov_al_32(void)
{
	pti_uint8_t insn[] = { 0xA1, 0x3f, 0xaa, 0xbb,
			       0xcc, 0xdd, 0xee, 0xfF,
			       0X11 };

	ptu_boring(insn, 5, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result mov_al_16(void)
{
	pti_uint8_t insn[] = { 0x66, 0xA1, 0x3f, 0xaa, 0xbb,
			       0xcc, 0xdd, 0xee, 0xfF,
			       0X11 };

	ptu_boring(insn, 4, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result rdtsc(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x31 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result pcmpistri(void)
{
	pti_uint8_t insn[] = { 0x66, 0x0f, 0x3a, 0x63, 0x04, 0x16, 0x1a };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result vmovdqa(void)
{
	pti_uint8_t insn[] = { 0xc5, 0xf9, 0x6f, 0x25, 0xa9, 0x55, 0x04, 0x00 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result vpandn(void)
{
	pti_uint8_t insn[] = { 0xc4, 0x41, 0x29, 0xdf, 0xd1 };

	ptu_boring_s(insn, PTI_MODE_64);

	return ptu_passed();
}

static struct ptunit_result syscall(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x05 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_SYSCALL);

	return ptu_passed();
}

static struct ptunit_result sysret(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x07 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_SYSRET);

	return ptu_passed();
}

static struct ptunit_result sysenter(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x34 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_SYSENTER);

	return ptu_passed();
}

static struct ptunit_result sysexit(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x35 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_SYSEXIT);

	return ptu_passed();
}

static struct ptunit_result int3(void)
{
	pti_uint8_t insn[] = { 0xcc };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_INT3);

	return ptu_passed();
}

static struct ptunit_result intn(void)
{
	pti_uint8_t insn[] = { 0xcd, 0x06 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_INT);

	return ptu_passed();
}

static struct ptunit_result iret(void)
{
	pti_uint8_t insn[] = { 0xcf };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_IRET);

	return ptu_passed();
}

static struct ptunit_result call_9a_cd(void)
{
	pti_uint8_t insn[] = { 0x9a, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_16, PTI_INST_CALL_9A);

	return ptu_passed();
}

static struct ptunit_result call_9a_cp(void)
{
	pti_uint8_t insn[] = { 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_32, PTI_INST_CALL_9A);

	return ptu_passed();
}

static struct ptunit_result call_ff_3(void)
{
	pti_uint8_t insn[] = { 0xff, 0x1c, 0x25, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_CALL_FFr3);

	return ptu_passed();
}

static struct ptunit_result jmp_ff_5(void)
{
	pti_uint8_t insn[] = { 0xff, 0x2c, 0x25, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_JMP_FFr5);

	return ptu_passed();
}

static struct ptunit_result jmp_ea_cd(void)
{
	pti_uint8_t insn[] = { 0xea, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_16, PTI_INST_JMP_EA);

	return ptu_passed();
}

static struct ptunit_result jmp_ea_cp(void)
{
	pti_uint8_t insn[] = { 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_32, PTI_INST_JMP_EA);

	return ptu_passed();
}

static struct ptunit_result ret_ca(void)
{
	pti_uint8_t insn[] = { 0xca, 0x00, 0x00 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_RET_CA);

	return ptu_passed();
}

static struct ptunit_result vmlaunch(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x01, 0xc2 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_VMLAUNCH);

	return ptu_passed();
}

static struct ptunit_result vmresume(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x01, 0xc3 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_VMRESUME);

	return ptu_passed();
}

static struct ptunit_result vmcall(void)
{
	pti_uint8_t insn[] = { 0x0f, 0x01, 0xc1 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_VMCALL);

	return ptu_passed();
}

static struct ptunit_result vmptrld(void)
{
	pti_uint8_t insn[] = { 0x0f, 0xc7, 0x30 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_VMPTRLD);

	return ptu_passed();
}

static struct ptunit_result jrcxz(void)
{
	pti_uint8_t insn[] = { 0xe3, 0x00 };

	ptu_classify_s(insn, PTI_MODE_64, PTI_INST_JrCXZ);

	return ptu_passed();
}

int main(int argc, char **argv)
{
	struct ptunit_suite suite;

	pti_ild_init();

	suite = ptunit_mk_suite(argc, argv);

	ptu_run(suite, push);
	ptu_run(suite, jmp_rel);
	ptu_run(suite, long_nop);
	ptu_run(suite, mov_al_64);
	ptu_run(suite, mov_al_32);
	ptu_run(suite, mov_al_16);
	ptu_run(suite, rdtsc);
	ptu_run(suite, pcmpistri);
	ptu_run(suite, vmovdqa);
	ptu_run(suite, vpandn);
	ptu_run(suite, syscall);
	ptu_run(suite, sysret);
	ptu_run(suite, sysenter);
	ptu_run(suite, sysexit);
	ptu_run(suite, int3);
	ptu_run(suite, intn);
	ptu_run(suite, iret);
	ptu_run(suite, call_9a_cd);
	ptu_run(suite, call_9a_cp);
	ptu_run(suite, call_ff_3);
	ptu_run(suite, jmp_ff_5);
	ptu_run(suite, jmp_ea_cd);
	ptu_run(suite, jmp_ea_cp);
	ptu_run(suite, ret_ca);
	ptu_run(suite, vmlaunch);
	ptu_run(suite, vmresume);
	ptu_run(suite, vmcall);
	ptu_run(suite, vmptrld);
	ptu_run(suite, jrcxz);

	ptunit_report(&suite);
	return suite.nr_fails;
}
