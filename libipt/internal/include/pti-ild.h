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

#if !defined(_PTI_ILD_H_)
#define _PTI_ILD_H_


#include "pti-defs.h"
#include "pti-types.h"

typedef enum
{
  PTI_INST_INVALID,

  PTI_INST_CALL_9A,
  PTI_INST_CALL_FFr3,
  PTI_INST_CALL_FFr2,
  PTI_INST_CALL_E8,
  PTI_INST_INT,

  PTI_INST_INT3,
  PTI_INST_INT1,
  PTI_INST_INTO,
  PTI_INST_IRET,                /* includes IRETD and IRETQ (EOSZ determines) */


  PTI_INST_JMP_E9,
  PTI_INST_JMP_EB,
  PTI_INST_JMP_EA,
  PTI_INST_JMP_FFr5,            /* REXW? */
  PTI_INST_JMP_FFr4,
  PTI_INST_JCC,
  PTI_INST_JrCXZ,
  PTI_INST_LOOP,
  PTI_INST_LOOPE,               /* aka Z */
  PTI_INST_LOOPNE,              /* aka NE */

  PTI_INST_MOV_CR3,

  PTI_INST_RET_C3,
  PTI_INST_RET_C2,
  PTI_INST_RET_CB,
  PTI_INST_RET_CA,

  PTI_INST_SYSCALL,
  PTI_INST_SYSENTER,
  PTI_INST_SYSEXIT,
  PTI_INST_SYSRET,

  PTI_INST_LAST
} pti_inst_enum_t;

typedef enum
{
  PTI_MODE_16,
  PTI_MODE_32,
  PTI_MODE_64,
  PTI_MODE_LAST
} pti_machine_mode_enum_t;
typedef enum
{
  PTI_MAP_0,                    /* may have modrm */
  PTI_MAP_1,                    /* may have modrm */
  PTI_MAP_2,                    /* has modrm */
  PTI_MAP_3,                    /* has modrm */
  PTI_MAP_AMD3DNOW,             /* has modrm */
  PTI_MAP_INVALID
} pti_map_enum_t;

typedef struct
{
  /* inputs */
  pti_uint64_t runtime_address;
  pti_uint8_t const *itext;
  pti_uint32_t max_bytes;       /*1..15 bytes  */
  pti_machine_mode_enum_t mode;

  /* outputs */
  pti_uint32_t length;          /* bytes */
  pti_inst_enum_t iclass;
  pti_uint64_t direct_target;   /* if direct_indirect = 1 */
  union
  {
    struct
    {
      /* all the errors come from not having enough bytes. */
      pti_uint32_t error:1;
      pti_uint32_t branch:1;    /* direct or indirect */

      /* direct jmp, direct call or rel/direct branch sets
         branch_direct = 1. */
      pti_uint32_t branch_direct:1;     /* 1=direct, 0=indirect */

      /* this includes other transfers like SYSENTER, SYSEXIT, and IRET. */
      pti_uint32_t branch_far:1; /* 1=far, 0=near */

      pti_uint32_t ret:1;
      pti_uint32_t call:1;
      pti_uint32_t cond:1;
      /* internal fields */
      pti_uint32_t osz:1;
      pti_uint32_t asz:1;
      pti_uint32_t lock:1;
      pti_uint32_t f3:1;
      pti_uint32_t f2:1;
      pti_uint32_t last_f2f3:2; /* 2 or 3 */
      pti_uint32_t vexc5:1;
      pti_uint32_t vexc4:1;
      pti_uint32_t sib:1;
    } s;
    pti_uint32_t i;
  } u;
  pti_uint8_t seg;
  pti_uint8_t nprefixes;
  pti_uint8_t rex;              /* 0b0100wrxb */
  pti_uint8_t c5byte1;
  pti_uint8_t c4byte1;
  pti_uint8_t c4byte2;
  pti_uint8_t map;     /* 5b but valid values=  0,1,2,3 could be in bit union */
  pti_uint8_t nominal_opcode;
  pti_uint8_t has_modrm;        /* opaque see pti-enums.h */
  pti_uint8_t modrm_byte;
  pti_uint8_t sib_byte;
  pti_uint8_t nominal_opcode_pos;
  pti_uint8_t imm1_bytes;       /* # of bytes in 1st immediate */
  pti_uint8_t imm2_bytes;       /* # of bytes in 2nd immediate */
  pti_uint8_t disp_pos;
  pti_uint8_t disp_bytes;       /* # of displacement bytes */
  /* not including imm_pos, could or could derive from disp_pos + disp_bytes */

} pti_ild_t;

PTI_INLINE void
pti_set_map (pti_ild_t * ild, pti_map_enum_t mape)
{
  ild->map = (pti_uint8_t) mape;
}

PTI_INLINE pti_map_enum_t
pti_get_map (pti_ild_t * ild)
{
  return (pti_map_enum_t) ild->map;
}

PTI_INLINE pti_uint_t
pti_get_sib_base (pti_ild_t * ild)
{
  return ild->sib_byte & 7;
}

PTI_INLINE pti_uint_t
pti_get_modrm_mod (pti_ild_t * ild)
{
  return ild->modrm_byte >> 6;
}

PTI_INLINE pti_uint_t
pti_get_modrm_reg (pti_ild_t * ild)
{
  return (ild->modrm_byte >> 3) & 7;
}

PTI_INLINE pti_uint_t
pti_get_modrm_rm (pti_ild_t * ild)
{
  return ild->modrm_byte & 7;
}


/* MAIN ENTRANCE POINTS */

/* one time call. not thread safe init. call when single threaded. */
void pti_ild_init (void);


/* all decoding is multithread safe. */

/* returns 1 on success, 0 on failure.
   Failures come from not having enough bytes
   to decode the instruction. (That might be because
   the instruction encoding implied >= 16B and that is an an invalid
   instruction.) */
pti_bool_t pti_instruction_length_decode (pti_ild_t * ild);

/* returns 1 if an interesting instruction was encountered. */
pti_bool_t pti_instruction_decode (pti_ild_t * ild);

#endif
