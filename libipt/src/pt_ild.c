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

#include "pti-defs.h"
#include "pti-ild.h"
#include "pti-enums.h"

#include <assert.h>
#include <stdlib.h>

PTI_INLINE PTI_NORETURN void
pti_abort ()
{
  /* this would be be a programming error. */
  assert (0);

  /* make sure to exit also for release builds. */
  exit(1);
}

/* SET UP 3 TABLES */

static pti_uint8_t has_disp_regular[3][4][8];

static void
init_has_disp_regular_table (void)
{
  pti_uint8_t eamode;
  pti_uint8_t rm;
  pti_uint8_t mod;

  /* zero whole table */
  for (eamode = 0; eamode < 3; eamode++)
    for (mod = 0; mod < 4; mod++)
      for (rm = 0; rm < 8; rm++)
        has_disp_regular[eamode][mod][rm] = 0;

  /*fill the eamode16 */
  has_disp_regular[0][0][6] = 2;
  for (rm = 0; rm < 8; rm++)
    {
      for (mod = 1; mod <= 2; mod++)
        has_disp_regular[0][mod][rm] = mod;
    }

  /*fill eamode32/64 */
  for (eamode = 1; eamode <= 2; eamode++)
    {
      for (rm = 0; rm < 8; rm++)
        {
          has_disp_regular[eamode][1][rm] = 1;
          has_disp_regular[eamode][2][rm] = 4;
        };
      has_disp_regular[eamode][0][5] = 4;
    }
}



static pti_uint8_t eamode_table[2][PTI_MODE_LAST];

static void
init_eamode_table (void)
{
  pti_uint8_t mode;
  pti_uint8_t asz;

  /* zero out the table. */
  for (asz = 0; asz < 2; asz++)
    for (mode = 0; mode < PTI_MODE_LAST; mode++)
      eamode_table[asz][mode] = 0;

  for (mode = PTI_MODE_16; mode <= PTI_MODE_64; mode++)
    eamode_table[0][mode] = mode;

  eamode_table[1][PTI_MODE_16] = PTI_MODE_32;
  eamode_table[1][PTI_MODE_32] = PTI_MODE_16;
  eamode_table[1][PTI_MODE_64] = PTI_MODE_32;
}

static pti_uint8_t has_sib_table[3][4][8];

static void
init_has_sib_table (void)
{
  pti_uint8_t eamode;
  pti_uint8_t mod;
  pti_uint8_t rm;

  /* zero whole table */
  for (eamode = 0; eamode < 3; eamode++)
    for (mod = 0; mod < 4; mod++)
      for (rm = 0; rm < 8; rm++)
        has_sib_table[eamode][mod][rm] = 0;

  /*for eamode32/64 there is sib byte for mod!=3 and rm==4 */
  for (eamode = 1; eamode <= 2; eamode++)
    {
      for (mod = 0; mod <= 2; mod++)
        {
          has_sib_table[eamode][mod][4] = 1;
        }
    }
}

/* SOME ACCESSORS */

PTI_INLINE pti_uint8_t
get_byte (pti_ild_t * ild, pti_uint_t i)
{
  return ild->itext[i];
}

PTI_INLINE pti_uint8_t const *
get_byte_ptr (pti_ild_t * ild, pti_uint_t i)
{
  return ild->itext + i;
}

PTI_INLINE pti_bool_t
mode_64b (pti_ild_t * ild)
{
  return ild->mode == PTI_MODE_64;
}

PTI_INLINE pti_bool_t
mode_32b (pti_ild_t * ild)
{
  return ild->mode == PTI_MODE_32;
}

PTI_INLINE pti_bool_t
bits_match (pti_uint8_t x, pti_uint8_t mask, pti_uint8_t target)
{
  return (x & mask) == target;
}

PTI_INLINE void
set_error (pti_ild_t * ild)
{
  ild->u.s.error = 1;
}

/* accessors for REX.R/VEX R  */
PTI_INLINE pti_uint_t
pti_get_rex_vex_r (pti_ild_t * ild)
{
  if (ild->u.s.vexc5)
    return (ild->c5byte1 >> 7) & 1;
  else if (ild->u.s.vexc4)
    return (ild->c4byte1 >> 7) & 1;
  else if (ild->rex)
    return (ild->rex >> 2) & 1;
  return 0;
}

PTI_INLINE pti_uint_t
pti_get_rex_vex_w (pti_ild_t * ild)
{
  if (ild->u.s.vexc5)
    return 0;
  else if (ild->u.s.vexc4)
    return (ild->c4byte2 >> 7) & 1;
  else if (ild->rex)
    return (ild->rex >> 3) & 1;
  return 0;
}

PTI_INLINE
  pti_machine_mode_enum_t pti_get_nominal_eosz_non64 (pti_ild_t * ild)
{
  if (mode_32b (ild))
    {
      if (ild->u.s.osz)
        return PTI_MODE_16;
      return PTI_MODE_32;
    }
  if (ild->u.s.osz)
    return PTI_MODE_32;
  return PTI_MODE_16;
}

PTI_INLINE pti_machine_mode_enum_t
pti_get_nominal_eosz (pti_ild_t * ild)
{
  if (mode_64b (ild))
    {
      if (pti_get_rex_vex_w (ild))
        return PTI_MODE_64;
      if (ild->u.s.osz)
        return PTI_MODE_16;
      return PTI_MODE_32;
    }
  return pti_get_nominal_eosz_non64 (ild);
}

PTI_INLINE pti_machine_mode_enum_t
pti_get_nominal_eosz_df64 (pti_ild_t * ild)
{
  if (mode_64b (ild))
    {
      if (pti_get_rex_vex_w (ild))
        return PTI_MODE_64;
      if (ild->u.s.osz)
        return PTI_MODE_16;
      /* only this next line of code is different relative
         to pti_get_nominal_eosz(), above */
      return PTI_MODE_64;
    }
  return pti_get_nominal_eosz_non64 (ild);
}

PTI_INLINE pti_uint_t
resolve_z (pti_machine_mode_enum_t eosz)
{
  static const pti_uint_t bytes[] = { 2, 4, 4 };
  if (eosz < PTI_MODE_LAST)
    return bytes[eosz];
  pti_abort ();
}

PTI_INLINE pti_uint_t
resolve_v (pti_machine_mode_enum_t eosz)
{
  static const pti_uint_t bytes[] = { 2, 4, 8 };
  if (eosz < PTI_MODE_LAST)
    return bytes[eosz];
  pti_abort ();
}

/*  DECODERS */

static void
prefix_rex_dec (pti_ild_t * ild)
{
  pti_uint_t max_bytes = ild->max_bytes;
  pti_uint_t length = 0;
  pti_uint_t rex = 0;
  pti_uint_t nprefixes = 0;

  while (length < max_bytes)
    {
      pti_uint8_t b = get_byte (ild, length);
      switch (b)
        {
        case 0x66:
          ild->u.s.osz = 1;
          /*ignore possible REX prefix encoutered earlier */
          rex = 0;
          break;

        case 0x67:
          ild->u.s.asz = 1;
          rex = 0;
          break;

          /* segment prefixes */
        case 0x2E:
        case 0x3E:
        case 0x26:
        case 0x36:
        case 0x64:
        case 0x65:
          /* ignore possible REX prefix encountered earlier */
          rex = 0;
          break;

        case 0xF0:
          ild->u.s.lock = 1;
          rex = 0;
          break;

        case 0xF3:
          ild->u.s.f3 = 1;
          ild->u.s.last_f2f3 = 3;
          rex = 0;
          break;

        case 0xF2:
          ild->u.s.f2 = 1;
          ild->u.s.last_f2f3 = 2;
          rex = 0;
          break;

        default:
          /*Take care of REX prefix */
          if (mode_64b (ild) && (b & 0xf0) == 0x40)
            {
              rex = b;
            }
          else
            goto out;
        }
      length++;
      nprefixes++;
    }
out:
  ild->length = length;
  ild->rex = (pti_uint8_t) rex;
  if (length >= max_bytes)
    {
      /* all available length was taken by prefixes, but we for sure need at
       * least one additional byte for an opcode, hence we are out of bytes.
       */
      set_error (ild);
      return;
    }
}

static void
vex_opcode_dec (pti_ild_t * ild)
{
  pti_uint_t length = ild->length;
  ild->nominal_opcode = get_byte (ild, length);
  ild->nominal_opcode_pos = (pti_uint8_t) length;     /*FIXME: needed? */
  ild->length = length + 1;
}

static void
vex_c5_dec (pti_ild_t * ild)
{
  pti_uint_t max_bytes = ild->max_bytes;
  pti_uint_t length = ild->length;
  if (mode_64b (ild))
    {
      ild->u.s.vexc5 = 1;
      length++;                 /* eat the c5 */
    }
  else if (length + 1 < max_bytes)
    {                           /* non64b mode */
      pti_uint8_t n = get_byte (ild, length);
      if (bits_match (n, 0xC0, 0xC0))
        {
          ild->u.s.vexc5 = 1;
          length++;             /* eat the c5 */
        }
      else
        {
          /* not c5 vex, keep going */
          return;
        }
    }
  else
    {
      set_error (ild);
      return;
    }

  /* vex payload processing */

  /* we want to make sure, that we have additional 2 bytes
   * available for reading - for vex payload byte and opcode */
  if ((length + 2) <= max_bytes)
    {
      ild->c5byte1 = get_byte (ild, length);
      pti_set_map (ild, PTI_MAP_1);
      length++;                 /* eat the vex payload byte */
      ild->length = length;
      vex_opcode_dec (ild);
    }
  else
    {
      set_error (ild);
    }
}

static void
vex_c4_dec (pti_ild_t * ild)
{
  pti_uint_t max_bytes = ild->max_bytes;
  pti_uint_t length = ild->length;
  if (mode_64b (ild))
    {
      ild->u.s.vexc4 = 1;
      length++;                 /* eat the c4 */
    }
  else if (length + 1 < max_bytes)
    {                           /* non64b mode */
      pti_uint8_t n = get_byte (ild, length);
      if (bits_match (n, 0xC0, 0xC0))
        {
          ild->u.s.vexc4 = 1;
          length++;             /* eat the c4 */
        }
      else
        {
          /* not c4 vex, keep going */
          return;
        }
    }
  else
    {
      set_error (ild);
      return;
    }

  /* vex payload processing */

  /* we want to make sure, that we have additional 2 bytes
   * available for reading - for vex payload byte and opcode */
  if ((length + 3) <= max_bytes)
    {
      ild->c4byte1 = get_byte (ild, length);
      ild->c4byte2 = get_byte (ild, length + 1);

      pti_set_map (ild, (pti_map_enum_t) (ild->c4byte1 & 0x1F));
      if (pti_get_map (ild) == PTI_MAP_3)
        ild->imm1_bytes = 1;

      length += 2;              /* eat the 2byte vex payload */
      ild->length = length;
      vex_opcode_dec (ild);
    }
  else
    {
      set_error (ild);
    }
}

static void
vex_dec (pti_ild_t * ild)
{
  /* prefix scanner checked length for us so we know at least 1B is left. */
  pti_uint8_t b = get_byte (ild, ild->length);
  if (b == 0xC5)
    vex_c5_dec (ild);
  else if (b == 0xC4)
    vex_c4_dec (ild);
}


static void
get_next_as_opcode (pti_ild_t * ild)
{
  pti_uint_t length = ild->length;
  if (length < ild->max_bytes)
    {
      ild->nominal_opcode = get_byte (ild, length);
      ild->nominal_opcode_pos = (pti_uint8_t) length;
      ild->length = length + 1;
    }
  else
    {
      set_error (ild);
    }
}


static void
opcode_dec (pti_ild_t * ild)
{
  pti_uint_t length = ild->length;
  pti_uint8_t b = get_byte (ild, length);
  /*no need to check max_bytes - it was checked in previous scanners */

  if (b != 0x0F)
    {                           /* 1B opcodes, map 0 */
      pti_set_map (ild, PTI_MAP_0);
      ild->nominal_opcode = b;
      ild->nominal_opcode_pos = (pti_uint8_t) length;
      ild->length = length + 1;
      return;
    }

  length++;                     /* eat the 0x0F */
  ild->nominal_opcode_pos = (pti_uint8_t) length;

  /* 0x0F opcodes MAPS 1,2,3 */
  if (length < ild->max_bytes)
    {
      pti_uint8_t m = get_byte (ild, length);
      if (m == 0x38)
        {
          length++;             /* eat the 0x38 */
          pti_set_map (ild, PTI_MAP_2);
          ild->length = length;
          get_next_as_opcode (ild);
          return;
        }
      else if (m == 0x3A)
        {
          length++;             /* eat the 0x3A */
          pti_set_map (ild, PTI_MAP_3);
          ild->length = length;
          ild->imm1_bytes = 1;
          get_next_as_opcode (ild);
          return;
        }
      else if (m == 0x3B)
        {
          length++;             /* eat the 0x3B */
          pti_set_map (ild, PTI_MAP_INVALID);
          ild->length = length;
          get_next_as_opcode (ild);
          return;
        }
      else if (m > 0x38 && m <= 0x3F)
        {
          length++;             /* eat the 0x39...0x3F (minus 3A and 3B) */
          pti_set_map (ild, PTI_MAP_INVALID);
          ild->length = length;
          get_next_as_opcode (ild);
          return;
        }
      else if (m == 0x0F)
        {                       /* 3dNow */
          pti_set_map (ild, PTI_MAP_AMD3DNOW);
          ild->imm1_bytes = 1;
          /* real opcode is in immediate later on, but we need an
           * opcode now. */
          ild->nominal_opcode = 0x0F;
          ild->length = length + 1;     /*eat the second 0F */
        }
      else
        {                       /* map 1 (simple two byte opcodes) */
          length++;             /* eat the 2nd  opcode byte */
          ild->nominal_opcode = m;
          ild->nominal_opcode_pos = (pti_uint8_t) length;
          pti_set_map (ild, PTI_MAP_1);
          ild->length = length;
        }
    }
  else
    {
      set_error (ild);
    }
}


#include "pti-modrm.h"
#include "pti-disp-defs.h"
#include "pti-disp.h"


static void
modrm_dec (pti_ild_t * ild)
{
  static pti_uint8_t const *const has_modrm_2d[2] = {
    has_modrm_map_0x0,
    has_modrm_map_0x0F
  };
  pti_uint_t has_modrm = PTI_MODRM_FALSE;

  pti_map_enum_t map = pti_get_map (ild);
  if (map >= PTI_MAP_2)
    has_modrm = PTI_MODRM_TRUE;
  else
    has_modrm = has_modrm_2d[map][ild->nominal_opcode];
  if (has_modrm == PTI_MODRM_FALSE)
    return;
  if (has_modrm == PTI_MODRM_UNDEF)     /*FIXME: what to do about these? */
    return;
  if (ild->length >= ild->max_bytes)
    {
      /* really >= here because we have not eaten the byte yet */
      set_error (ild);
      return;
    }
  ild->modrm_byte = get_byte (ild, ild->length);
  ild->length++;                /* eat modrm */
  if (has_modrm != PTI_MODRM_IGNORE_MOD)
    {
      /* set disp_bytes and sib using simple tables */

      pti_uint8_t eamode = eamode_table[ild->u.s.asz][ild->mode];
      pti_uint8_t mod = (pti_uint8_t) pti_get_modrm_mod(ild);
      pti_uint8_t rm = (pti_uint8_t) pti_get_modrm_rm(ild);

      ild->disp_bytes = has_disp_regular[eamode][mod][rm];
      ild->u.s.sib = has_sib_table[eamode][mod][rm];
    }

}

static void
sib_dec (pti_ild_t * ild)
{
  if (ild->u.s.sib)
    {
      pti_uint_t length = ild->length;
      if (length < ild->max_bytes)
        {
          ild->sib_byte = get_byte (ild, length);
          ild->length = length + 1;
          if (pti_get_sib_base (ild) == 5 && pti_get_modrm_mod (ild) == 0)
            ild->disp_bytes = 4;
        }
      else
        {
          set_error (ild);
        }
    }
}

static void
compute_disp_dec (pti_ild_t * ild)
{
  /* set ild->disp_bytes for maps 0 and 1. */
  static pti_uint8_t const *const map_map[] = {
    /* map 0 */ disp_bytes_map_0x0,
    /* map 1 */ disp_bytes_map_0x0F,
    /* map 2 */ 0,
    /* map 3 */ 0,
    /* amd3dnow */ 0,
    /* invalid */ 0
  };

  pti_uint8_t const *const disp_table = map_map[ild->map];
  pti_uint_t disp_kind;

  if (disp_table == 0)
    return;
  disp_kind = disp_table[ild->nominal_opcode];
  switch (disp_kind)
    {
    case PTI_DISP_NONE:
      ild->disp_bytes = 0;
      break;
    case PTI_PRESERVE_DEFAULT:
      /* nothing to do */
      break;
    case PTI_BRDISP8:
      ild->disp_bytes = 1;
      break;
    case PTI_DISP_BUCKET_0_l1:
      /* BRDISPz(eosz) for 16/32 modes, and BRDISP32 for 64b mode */
      if (mode_64b (ild))
        ild->disp_bytes = 4;
      else
        {
          pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
          ild->disp_bytes = (pti_uint8_t) resolve_z(eosz);
        }
      break;
    case PTI_MEMDISPv_DISP_WIDTH_ASZ_NONTERM_EASZ_l2:
      /* MEMDISPv(easz) */
      {
        pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
        ild->disp_bytes = (pti_uint8_t) resolve_v(eosz);
      }
      break;
    case PTI_BRDISPz_BRDISP_WIDTH_OSZ_NONTERM_EOSZ_l2:
      /* BRDISPz(eosz) for 16/32/64 modes */
      {
        pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
        ild->disp_bytes = (pti_uint8_t) resolve_z(eosz);
      }
      break;
    case PTI_RESOLVE_BYREG_DISP_map0x0_op0xc7_l1:
      /* reg=0 -> preserve, reg=7 -> BRDISPz(eosz) */
      if (ild->map == PTI_MAP_0 && pti_get_modrm_reg (ild) == 7)
        {
          pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
          ild->disp_bytes = (pti_uint8_t) resolve_z(eosz);
        }
      break;
    default:
      pti_abort ();
    }
}

static void
disp_dec (pti_ild_t * ild)
{
  pti_uint_t disp_bytes;
  if (ild->disp_bytes == 0 && pti_get_map (ild) < PTI_MAP_2)
    {
      compute_disp_dec (ild);
    }
  disp_bytes = ild->disp_bytes;
  if (disp_bytes == 0)
    return;
  if (ild->length + disp_bytes > ild->max_bytes)
    {
      set_error (ild);
      return;
    }

  /*Record only position; must be able to re-read itext bytes for actual 
     value. (SMC/CMC issue). */
  ild->disp_pos = (pti_uint8_t) ild->length;
  ild->length += disp_bytes;
}


#include "pti-imm-defs.h"
#include "pti-imm.h"

static void
set_imm_bytes (pti_ild_t * ild)
{
  /*: set ild->imm1_bytes and  ild->imm2_bytes for maps 0/1 */
  static pti_uint8_t const *const map_map[] = {
    /* map 0 */ imm_bytes_map_0x0,
    /* map 1 */ imm_bytes_map_0x0F,
    /* map 2 */ 0,
    /* map 3 */ 0,
    /* amd3dnow */ 0,
    /* invalid */ 0
  };
  pti_uint8_t const *const map_imm = map_map[ild->map];
  pti_uint_t imm_code;

  if (map_imm == 0)
    return;
  imm_code = map_imm[ild->nominal_opcode];
  switch (imm_code)
    {
    case PTI_IMM_NONE:
    case PTI_0_IMM_WIDTH_CONST_l2:
      /* nothing for either case */
      break;
    case PTI_UIMM8_IMM_WIDTH_CONST_l2:
      ild->imm1_bytes = 1;
      break;
    case PTI_SIMM8_IMM_WIDTH_CONST_l2:
      ild->imm1_bytes = 1;
      break;

    case PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2:
      /* SIMMz(eosz) */
      {
        pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
        ild->imm1_bytes = (pti_uint8_t) resolve_z(eosz);
      }
      break;
    case PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2:
      /* UIMMv(eosz) */
      {
        pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
        ild->imm1_bytes = (pti_uint8_t) resolve_v(eosz);
      }

      break;
    case PTI_UIMM16_IMM_WIDTH_CONST_l2:
      ild->imm1_bytes = 2;
      break;
    case PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_DF64_EOSZ_l2:
      /* push defaults to eosz64 in 64b mode, then uses SIMMz */
      {
        pti_machine_mode_enum_t eosz = pti_get_nominal_eosz_df64 (ild);
        ild->imm1_bytes = (pti_uint8_t) resolve_z(eosz);
      }
      break;
    case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf7_l1:
      if (ild->map == PTI_MAP_0 && pti_get_modrm_reg (ild) < 2)
        {
          pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
          ild->imm1_bytes = (pti_uint8_t) resolve_z(eosz);
        }
      break;
    case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xc7_l1:
      if (ild->map == PTI_MAP_0 && pti_get_modrm_reg (ild) == 0)
        {
          pti_machine_mode_enum_t eosz = pti_get_nominal_eosz (ild);
          ild->imm1_bytes = (pti_uint8_t) resolve_z(eosz);
        }
      break;
    case PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf6_l1:
      if (ild->map == PTI_MAP_0 && pti_get_modrm_reg (ild) < 2)
        {
          ild->imm1_bytes = 1;
        }
      break;
    case PTI_IMM_hasimm_map0x0_op0xc8_l1:
      if (ild->map == PTI_MAP_0)
        {
          /*enter -> imm1=2, imm2=1 */
          ild->imm1_bytes = 2;
          ild->imm2_bytes = 1;
        }
      break;
    case PTI_IMM_hasimm_map0x0F_op0x78_l1:
      /* AMD SSE4a (insertq/extrq use  osz/f2) vs vmread (no prefixes) */
      if (ild->map == PTI_MAP_1)
        {
          if (ild->u.s.osz || ild->u.s.last_f2f3 == 2)
            {
              ild->imm1_bytes = 1;
              ild->imm2_bytes = 1;
            }
        }
      break;
    default:
      break;
    }
}

static void
imm_dec (pti_ild_t * ild)
{
  if (ild->map == PTI_MAP_AMD3DNOW)
    {
      if (ild->length < ild->max_bytes)
        {
          ild->nominal_opcode = get_byte (ild, ild->length);
          ild->length++;
        }
      else
        set_error (ild);
      return;
    }
  set_imm_bytes (ild);
  if (ild->imm1_bytes == 0)
    return;

  if (ild->length + ild->imm1_bytes > ild->max_bytes)
    {
      set_error (ild);
      return;
    }
  /*FIXME: could record immediate position if ever needed... */
  ild->length += ild->imm1_bytes;

  if (ild->imm2_bytes == 0)
    return;

  if (ild->length + ild->imm2_bytes > ild->max_bytes)
    {
      set_error (ild);
      return;
    }
  ild->length += ild->imm2_bytes;
}

static void
decode (pti_ild_t * ild)
{
  prefix_rex_dec (ild);
  vex_dec (ild);
  if (ild->nominal_opcode_pos == 0)
    opcode_dec (ild);
  modrm_dec (ild);
  sib_dec (ild);
  disp_dec (ild);
  imm_dec (ild);
}

PTI_INLINE pti_int64_t
sign_extend_bq (pti_int8_t x)
{
  return x;
}

PTI_INLINE pti_int64_t
sign_extend_wq (pti_int16_t x)
{
  return x;
}

PTI_INLINE pti_int64_t
sign_extend_dq (pti_int32_t x)
{
  return x;
}

static void
set_branch_target (pti_ild_t * ild)
{
  pti_int64_t npc;
  pti_uint64_t sign_extended_disp = 0;
  if (ild->disp_bytes == 1)
    sign_extended_disp = sign_extend_bq (get_byte (ild, ild->disp_pos));
  else if (ild->disp_bytes == 2)
    {
      pti_int16_t *w = (pti_int16_t *) (get_byte_ptr (ild, ild->disp_pos));
      sign_extended_disp = sign_extend_wq (*w);
    }
  else if (ild->disp_bytes == 4)
    {
      pti_int32_t *d = (pti_int32_t *) (get_byte_ptr (ild, ild->disp_pos));
      sign_extended_disp = sign_extend_dq (*d);
    }
  else
    pti_abort ();
  npc = (pti_int64_t) (ild->runtime_address + ild->length);
  ild->direct_target = (pti_uint64_t) (npc + sign_extended_disp);
}

/*  MAIN ENTRY POINTS */

PTI_DLL_EXPORT void
pti_ild_init (void)
{                               /* initialization */
  init_has_disp_regular_table ();
  init_has_sib_table ();
  init_eamode_table ();
}

PTI_DLL_EXPORT pti_bool_t
pti_instruction_length_decode (pti_ild_t * ild)
{
  ild->u.i = 0;
  ild->imm1_bytes = 0;
  ild->imm2_bytes = 0;
  ild->disp_bytes = 0;
  ild->nominal_opcode_pos = 0;
  ild->modrm_byte = 0;
  ild->map = PTI_MAP_INVALID;

  decode (ild);
  return ild->u.s.error == 0;
}

PTI_DLL_EXPORT pti_bool_t
pti_instruction_decode (pti_ild_t * ild)
{
  pti_uint8_t opcode = ild->nominal_opcode;
  pti_uint8_t map = pti_get_map (ild);

  /*FIXME: finish pti_instruction_decode, validate prefixes or absense of. */
  ild->iclass = PTI_INST_INVALID;

  if (ild->map > PTI_MAP_1)
    return 0;                   /* uninteresting */
  if (ild->u.s.vexc4 || ild->u.s.vexc5)
    return 0;                   /* uninteresting */

  /* PTI_INST_JCC,   70...7F, 0F (0x80...0x8F) */
  if (opcode >= 0x70 && opcode <= 0x7F)
    {                           /*Jcc MAP0 */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_JCC;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;
    }
  if (opcode >= 0x80 && opcode <= 0x8F)
    {                           /*Jcc MAP1 */
      if (map == PTI_MAP_1)
        {
          ild->iclass = PTI_INST_JCC;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;
    }

  switch (ild->nominal_opcode)
    {
    case 0x9A:                 /* CALL far direct */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_CALL_9A;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.call = 1;
          return 1;
        }
      return 0;

    case 0xFF:               /* CALL with /r = /2 and /3, JMP with /4 and /5 */
      if (map == PTI_MAP_0)
        {
          pti_uint_t reg = pti_get_modrm_reg (ild);
          if (reg == 2)
            {
              ild->iclass = PTI_INST_CALL_FFr2;
              ild->u.s.branch = 1;
              ild->u.s.call = 1;
              return 1;
            }
          else if (reg == 3)
            {
              ild->iclass = PTI_INST_CALL_FFr3;
              ild->u.s.branch = 1;
              ild->u.s.branch_far = 1;
              ild->u.s.call = 1;
              return 1;
            }
          else if (reg == 4)
            {
              ild->iclass = PTI_INST_JMP_FFr4;
              ild->u.s.branch = 1;
              return 1;
            }
          else if (reg == 5)
            {
              ild->iclass = PTI_INST_JMP_FFr5;
              ild->u.s.branch = 1;
              ild->u.s.branch_far = 1;
              return 1;
            }
        }
      return 0;
    case 0xE8:                 /* CALL */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_CALL_E8;
          ild->u.s.branch = 1;
          ild->u.s.call = 1;
          ild->u.s.branch_direct = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;

    case 0xCD:                 /* INT */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_INT;
          return 1;
        }
      return 0;

    case 0xCC:                 /* INT3 */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_INT3;
          return 1;
        }
      return 0;
    case 0xCE:                 /* INTO */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_INTO;
          return 1;
        }
      return 0;
    case 0xF1:                 /* INT1 */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_INT1;
          return 1;
        }
      return 0;

    case 0xCF:                 /* PTI_INST_IRET (includes IRETD/IRETQ) */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_IRET;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;

    case 0xE9:                 /* JMP */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_JMP_E9;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;

    case 0xEA:              /* JMP - far jump -- FIXME: do we compute target? */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_JMP_EA;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          return 1;
        }
      return 0;
    case 0xEB:                 /* JMP */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_JMP_EB;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;

    case 0xE3:                 /* JRCXZ */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_JrCXZ;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;

    case 0xE0:                 /* LOOPNE */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_LOOPNE;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;
    case 0xE1:                 /* LOOPE */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_LOOPE;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;
    case 0xE2:                 /* LOOP */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_LOOP;
          ild->u.s.branch = 1;
          ild->u.s.branch_direct = 1;
          ild->u.s.cond = 1;
          set_branch_target (ild);
          return 1;
        }
      return 0;

    case 0x22:                 /* MOV to CR in map 1 , check for reg 3 */
      if (map == PTI_MAP_1)
        if (pti_get_modrm_reg (ild) == 3)
          if (pti_get_rex_vex_r (ild) == 0) {
            ild->iclass = PTI_INST_MOV_CR3;
            return 1;
          }
      return 0;

    case 0xC3:                 /* PTI_INST_RET_C3, */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_RET_C3;
          ild->u.s.branch = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;

    case 0xC2:                 /* PTI_INST_RET_C2, */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_RET_C2;
          ild->u.s.branch = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;
    case 0xCB:                 /* PTI_INST_RET_CB, */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_RET_CB;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;
    case 0xCA:                 /* PTI_INST_RET_CA, */
      if (map == PTI_MAP_0)
        {
          ild->iclass = PTI_INST_RET_CA;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;

    case 0x05:                 /* map 1 PTI_INST_SYSCALL, */
      if (map == PTI_MAP_1)
        {
          ild->iclass = PTI_INST_SYSCALL;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.call = 1;
          return 1;
        }
      return 0;
    case 0x34:                 /* map 1 PTI_INST_SYSENTER, */
      if (map == PTI_MAP_1)
        {
          ild->iclass = PTI_INST_SYSENTER;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.call = 1;
          return 1;
        }
      return 0;
    case 0x35:                 /* map 1 PTI_INST_SYSEXIT, */
      if (map == PTI_MAP_1)
        {
          ild->iclass = PTI_INST_SYSEXIT;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;
    case 0x07:                 /* map 1 PTI_INST_SYSRET, */
      if (map == PTI_MAP_1)
        {
          ild->iclass = PTI_INST_SYSRET;
          ild->u.s.branch = 1;
          ild->u.s.branch_far = 1;
          ild->u.s.ret = 1;
          return 1;
        }
      return 0;

    case 0x01:                 /* map 1 PTI_INST_VMLAUNCH/RESUME/CALL, */
      if (map == PTI_MAP_1)
        {
          switch (ild->modrm_byte)
            {
            case 0xc1:
              ild->iclass = PTI_INST_VMCALL;
              ild->u.s.branch = 1;
              ild->u.s.branch_far = 1;
              ild->u.s.ret = 1;
              return 1;

            case 0xc2:
              ild->iclass = PTI_INST_VMLAUNCH;
              ild->u.s.branch = 1;
              ild->u.s.branch_far = 1;
              ild->u.s.call = 1;
              return 1;

            case 0xc3:
              ild->iclass = PTI_INST_VMRESUME;
              ild->u.s.branch = 1;
              ild->u.s.branch_far = 1;
              ild->u.s.call = 1;
              return 1;

            default:
              return 0;
            }
        }
      return 0;

    case 0xc7:                 /* map 1 PTI_INST_VMPTRLD, */
      if (map == PTI_MAP_1 &&
          pti_get_modrm_mod (ild) != 3 &&
          pti_get_modrm_reg (ild) == 6)
        {
          ild->iclass = PTI_INST_VMPTRLD;
          return 1;
        }
      return 0;

    default:
      break;
    }

  return 0;

}
