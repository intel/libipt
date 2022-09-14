/*
 * Copyright (c) 2013-2022, Intel Corporation
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

static uint8_t imm_bytes_map_0x0[256] = {
/*opcode 0x0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x5*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xd*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xe*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf*/ 0,
/*opcode 0x10*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x11*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x12*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x13*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x14*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x15*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x16*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x17*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x18*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x19*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1c*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x1d*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x1e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x20*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x21*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x22*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x23*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x24*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x25*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x26*/ 0,
/*opcode 0x27*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x28*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x29*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2c*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x2d*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x2e*/ 0,
/*opcode 0x2f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x30*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x31*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x32*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x33*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x34*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x35*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x36*/ 0,
/*opcode 0x37*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x38*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x39*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x3a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x3b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x3c*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x3d*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x3e*/ 0,
/*opcode 0x3f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x40*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x41*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x42*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x43*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x44*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x45*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x46*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x47*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x48*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x49*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x50*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x51*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x52*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x53*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x54*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x55*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x56*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x57*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x58*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x59*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x60*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x61*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x62*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x63*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x64*/ 0,
/*opcode 0x65*/ 0,
/*opcode 0x66*/ 0,
/*opcode 0x67*/ 0,
/*opcode 0x68*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_DF64_EOSZ_l2,
/*opcode 0x69*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x6a*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x6b*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x6c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x70*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x71*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x72*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x73*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x74*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x75*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x76*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x77*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x78*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x79*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x80*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x81*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0x82*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x83*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x84*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x85*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x86*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x87*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x88*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x89*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x90*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x91*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x92*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x93*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x94*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x95*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x96*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x97*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x98*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x99*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9a*/ PTI_UIMM16_IMM_WIDTH_CONST_l2,
/*opcode 0x9b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa8*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xa9*/ PTI_SIMMz_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xaa*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xab*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xac*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xad*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xae*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xaf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb0*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb1*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb2*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb3*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb4*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb5*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb6*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb7*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xb8*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xb9*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xba*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xbb*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xbc*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xbd*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xbe*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xbf*/ PTI_UIMMv_IMM_WIDTH_OSZ_NONTERM_EOSZ_l2,
/*opcode 0xc0*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc1*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc2*/ PTI_UIMM16_IMM_WIDTH_CONST_l2,
/*opcode 0xc3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc6*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc7*/ PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xc7_l1,
/*opcode 0xc8*/ PTI_IMM_hasimm_map0x0_op0xc8_l1,
/*opcode 0xc9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xca*/ PTI_UIMM16_IMM_WIDTH_CONST_l2,
/*opcode 0xcb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcd*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xce*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd4*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xd5*/ PTI_SIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xd6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xda*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xde*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe4*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xe5*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xe6*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xe7*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xe8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xea*/ PTI_UIMM16_IMM_WIDTH_CONST_l2,
/*opcode 0xeb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xec*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xed*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xee*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xef*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf0*/ 0,
/*opcode 0xf1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf2*/ 0,
/*opcode 0xf3*/ 0,
/*opcode 0xf4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf6*/ PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf6_l1,
/*opcode 0xf7*/ PTI_RESOLVE_BYREG_IMM_WIDTH_map0x0_op0xf7_l1,
/*opcode 0xf8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfa*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfe*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xff*/ PTI_0_IMM_WIDTH_CONST_l2,
};
static uint8_t imm_bytes_map_0x0F[256] = {
/*opcode 0x0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4*/ 0,
/*opcode 0x5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa*/ 0,
/*opcode 0xb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc*/ 0,
/*opcode 0xd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf*/ 0,
/*opcode 0x10*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x11*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x12*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x13*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x14*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x15*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x16*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x17*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x18*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x19*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x1f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x20*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x21*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x22*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x23*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x24*/ 0,
/*opcode 0x25*/ 0,
/*opcode 0x26*/ 0,
/*opcode 0x27*/ 0,
/*opcode 0x28*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x29*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x2f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x30*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x31*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x32*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x33*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x34*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x35*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x36*/ 0,
/*opcode 0x37*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x38*/ 0,
/*opcode 0x39*/ 0,
/*opcode 0x3a*/ 0,
/*opcode 0x3b*/ 0,
/*opcode 0x3c*/ 0,
/*opcode 0x3d*/ 0,
/*opcode 0x3e*/ 0,
/*opcode 0x3f*/ 0,
/*opcode 0x40*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x41*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x42*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x43*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x44*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x45*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x46*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x47*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x48*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x49*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x4f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x50*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x51*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x52*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x53*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x54*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x55*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x56*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x57*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x58*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x59*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x5f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x60*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x61*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x62*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x63*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x64*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x65*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x66*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x67*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x68*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x69*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x6f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x70*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x71*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x72*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x73*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0x74*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x75*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x76*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x77*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x78*/ PTI_IMM_hasimm_map0x0F_op0x78_l1,
/*opcode 0x79*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x7f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x80*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x81*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x82*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x83*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x84*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x85*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x86*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x87*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x88*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x89*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x8f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x90*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x91*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x92*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x93*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x94*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x95*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x96*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x97*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x98*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x99*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9a*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9b*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9c*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9d*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9e*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0x9f*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa4*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xa5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa6*/ 0,
/*opcode 0xa7*/ 0,
/*opcode 0xa8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xa9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xaa*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xab*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xac*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xad*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xae*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xaf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xb9*/ 0,
/*opcode 0xba*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xbb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xbc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xbd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xbe*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xbf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc2*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc4*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc5*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc6*/ PTI_UIMM8_IMM_WIDTH_CONST_l2,
/*opcode 0xc7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xc9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xca*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xce*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xcf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xd9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xda*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xde*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xdf*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xe9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xea*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xeb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xec*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xed*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xee*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xef*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf0*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf1*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf2*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf3*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf4*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf5*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf6*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf7*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf8*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xf9*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfa*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfb*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfc*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfd*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xfe*/ PTI_0_IMM_WIDTH_CONST_l2,
/*opcode 0xff*/ 0,
};
