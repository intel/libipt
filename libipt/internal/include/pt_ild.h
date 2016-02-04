/*
 * Copyright (c) 2013-2016, Intel Corporation
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

#if !defined(PT_ILD_H)
#define PT_ILD_H

#include "intel-pt.h"

typedef enum {
	PTI_INST_INVALID,

	PTI_INST_CALL_9A,
	PTI_INST_CALL_FFr3,
	PTI_INST_CALL_FFr2,
	PTI_INST_CALL_E8,
	PTI_INST_INT,

	PTI_INST_INT3,
	PTI_INST_INT1,
	PTI_INST_INTO,
	PTI_INST_IRET,	/* includes IRETD and IRETQ (EOSZ determines) */

	PTI_INST_JMP_E9,
	PTI_INST_JMP_EB,
	PTI_INST_JMP_EA,
	PTI_INST_JMP_FFr5,	/* REXW? */
	PTI_INST_JMP_FFr4,
	PTI_INST_JCC,
	PTI_INST_JrCXZ,
	PTI_INST_LOOP,
	PTI_INST_LOOPE,	/* aka Z */
	PTI_INST_LOOPNE,	/* aka NE */

	PTI_INST_MOV_CR3,

	PTI_INST_RET_C3,
	PTI_INST_RET_C2,
	PTI_INST_RET_CB,
	PTI_INST_RET_CA,

	PTI_INST_SYSCALL,
	PTI_INST_SYSENTER,
	PTI_INST_SYSEXIT,
	PTI_INST_SYSRET,

	PTI_INST_VMLAUNCH,
	PTI_INST_VMRESUME,
	PTI_INST_VMCALL,
	PTI_INST_VMPTRLD,

	PTI_INST_LAST
} pti_inst_enum_t;

typedef enum {
	PTI_MAP_0,	/* 1-byte opcodes.           may have modrm */
	PTI_MAP_1,	/* 2-byte opcodes (0x0f).    may have modrm */
	PTI_MAP_2,	/* 3-byte opcodes (0x0f38).  has modrm */
	PTI_MAP_3,	/* 3-byte opcodes (0x0f3a).  has modrm */
	PTI_MAP_AMD3DNOW,	/* 3d-now opcodes (0x0f0f).  has modrm */
	PTI_MAP_INVALID
} pti_map_enum_t;

struct pt_ild {
	/* inputs */
	uint64_t runtime_address;
	uint8_t const *itext;
	uint8_t max_bytes;	/*1..15 bytes  */
	enum pt_exec_mode mode;

	/* outputs */
	uint8_t length;	/* bytes */
	pti_inst_enum_t iclass;
	uint64_t direct_target;	/* if direct_indirect = 1 */
	union {
		struct {
			uint32_t branch:1;	/* direct or indirect */

			/* direct jmp, direct call or rel/direct branch sets
			 * branch_direct = 1.
			 *
			 * 1=direct, 0=indirect
			 */
			uint32_t branch_direct:1;

			/* this includes other transfers like SYSENTER,
			 * SYSEXIT, and IRET.
			 *
			 * 1=far, 0=near
			 */
			uint32_t branch_far:1;

			uint32_t ret:1;
			uint32_t call:1;
			uint32_t cond:1;
			/* internal fields */
			uint32_t osz:1;
			uint32_t asz:1;
			uint32_t lock:1;
			uint32_t f3:1;
			uint32_t f2:1;
			uint32_t last_f2f3:2;	/* 2 or 3 */
			/* The vex bit is set for c4/c5 VEX and EVEX. */
			uint32_t vex:1;
			/* The REX.R and REX.W bits in REX, VEX, or EVEX. */
			uint32_t rex_r:1;
			uint32_t rex_w:1;
		} s;
		uint32_t i;
	} u;
	uint8_t imm1_bytes;	/* # of bytes in 1st immediate */
	uint8_t imm2_bytes;	/* # of bytes in 2nd immediate */
	uint8_t disp_bytes;	/* # of displacement bytes */
	uint8_t modrm_byte;
	/* 5b but valid values=  0,1,2,3 could be in bit union */
	uint8_t map;
	uint8_t rex;	/* 0b0100wrxb */
	uint8_t nominal_opcode;
	uint8_t disp_pos;
	/* imm_pos can be derived from disp_pos + disp_bytes. */
};

static inline pti_map_enum_t pti_get_map(struct pt_ild *ild)
{
	return (pti_map_enum_t) ild->map;
}

static inline uint8_t pti_get_modrm_mod(struct pt_ild *ild)
{
	return ild->modrm_byte >> 6;
}

static inline uint8_t pti_get_modrm_reg(struct pt_ild *ild)
{
	return (ild->modrm_byte >> 3) & 7;
}

static inline uint8_t pti_get_modrm_rm(struct pt_ild *ild)
{
	return ild->modrm_byte & 7;
}

/* MAIN ENTRANCE POINTS */

/* one time call. not thread safe init. call when single threaded. */
extern void pt_ild_init(void);

/* all decoding is multithread safe. */

/* Returns zero on success, a negative error code otherwise. */
extern int pt_instruction_length_decode(struct pt_ild *ild);

/* Returns a positive number if an interesting instruction was encountered.
 * Returns zero if a non-interesting instruction was encountered.
 * Returns a negative error code otherwise.
 */
extern int pt_instruction_decode(struct pt_ild *ild);

#endif /* PT_ILD_H */
