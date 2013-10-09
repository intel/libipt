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

#ifndef __PT_OPCODE_H__
#define __PT_OPCODE_H__


/* A one byte opcode. */
enum pt_opcode {
	pt_opc_pad		= 0x00,
	pt_opc_ext		= 0x02,
	pt_opc_psb		= pt_opc_ext,
	pt_opc_tip		= 0x0d,
	pt_opc_tnt_8		= 0x00,
	pt_opc_tip_pge		= 0x11,
	pt_opc_tip_pgd		= 0x01,
	pt_opc_fup		= 0x1d,
	pt_opc_mode		= 0x99,
	pt_opc_tsc		= 0x19,

	/* A free opcode to trigger a decode fault. */
	pt_opc_bad		= 0x59,
};

/* A one byte extension code for ext opcodes. */
enum pt_ext_code {
	pt_ext_psb		= 0x82,
	pt_ext_tnt_64		= 0xa3,
	pt_ext_pip		= 0x43,
	pt_ext_ovf		= 0xf3,
	pt_ext_psbend		= 0x23,
	pt_ext_cbr		= 0x03,

	pt_ext_bad		= 0x04,
};

/* A one byte opcode mask. */
enum pt_opcode_mask {
	pt_opm_tip		= 0x1f,
	pt_opm_tnt_8		= 0x01,
	pt_opm_tnt_8_shr	= 1,
	pt_opm_fup		= pt_opm_tip,

	/* The bit mask for the compression bits in the opcode. */
	pt_opm_ipc		= 0xe0,

	/* The shift right value for ipc bits. */
	pt_opm_ipc_shr		= 5,

	/* The bit mask for the compression bits after shifting. */
	pt_opm_ipc_shr_mask	= 0x7,
};

/* The size of the various opcodes in bytes. */
enum pt_opcode_size {
	pt_opcs_pad		= 1,
	pt_opcs_tip		= 1,
	pt_opcs_tip_pge		= 1,
	pt_opcs_tip_pgd		= 1,
	pt_opcs_fup		= 1,
	pt_opcs_tnt_8		= 1,
	pt_opcs_mode		= 1,
	pt_opcs_tsc		= 1,
	pt_opcs_psb		= 2,
	pt_opcs_psbend		= 2,
	pt_opcs_ovf		= 2,
	pt_opcs_pip		= 2,
	pt_opcs_tnt_64		= 2,
	pt_opcs_cbr		= 2,
};

/* The psb magic payload.
 *
 * The payload is a repeating 2-byte pattern.
 */
enum pt_psb_pattern {
	/* The high and low bytes in the pattern. */
	pt_psb_hi		= pt_opc_psb,
	pt_psb_lo		= pt_ext_psb,

	/* Various combinations of the above parts. */
	pt_psb_lohi		= pt_psb_lo | pt_psb_hi << 8,
	pt_psb_hilo		= pt_psb_hi | pt_psb_lo << 8,

	/* The repeat count of the payload, not including opc and ext. */
	pt_psb_repeat_count	= 7,

	/* The size of the repeated pattern in bytes. */
	pt_psb_repeat_size	= 2,
};

/* The IP compression. */
enum pt_ip_compression {
	/* The bits encode the payload size and the encoding scheme.
	 *
	 * No payload.  The IP has been suppressed.
	 */
	pt_ipc_suppressed	= 0x0,

	/* Payload: 16 bits.  Update last IP. */
	pt_ipc_update_16	= 0x01,

	/* Payload: 32 bits.  Update last IP. */
	pt_ipc_update_32	= 0x02,

	/* Payload: 48 bits.  Sign extend to full address. */
	pt_ipc_sext_48		= 0x03,
};

/* An execution mode. */
enum pt_exec_mode {
	ptem_unknown,
	ptem_16bit,
	ptem_32bit,
	ptem_64bit
};

/* The payload details. */
enum pt_payload {
	/* The shift counts for post-processing the PIP payload. */
	pt_pl_pip_shr		= 1,
	pt_pl_pip_shl		= 5,

	/* The size of a PIP payload in bytes. */
	pt_pl_pip_size		= 6,

	/* The size of a 8bit TNT packet's payload in bits. */
	pt_pl_tnt_8_bits	= 8 - pt_opm_tnt_8_shr,

	/* The size of a 64bit TNT packet's payload in bytes. */
	pt_pl_tnt_64_size	= 6,

	/* The size of a 64bit TNT packet's payload in bits. */
	pt_pl_tnt_64_bits	= 48,

	/* The size of a TSC packet's payload in bytes. */
	pt_pl_tsc_size		= 7,

	/* The size of a CBR packet's payload in bytes. */
	pt_pl_cbr_size		= 2,

	/* The size of a PSB packet's payload in bytes. */
	pt_pl_psb_size		= pt_psb_repeat_count * pt_psb_repeat_size,

	/* The size of a MODE packet's payload in bytes. */
	pt_pl_mode_size		= 1,

	/* The size of an IP packet's payload with update-16 compression. */
	pt_pl_ip_upd16_size	= 2,

	/* The size of an IP packet's payload with update-32 compression. */
	pt_pl_ip_upd32_size	= 4,

	/* The size of an IP packet's payload with sext-48 compression. */
	pt_pl_ip_sext48_size	= 6,
};

/* Mode packet masks. */
enum pt_mode_mask {
	pt_mom_leaf		= 0xe0,
	pt_mom_leaf_shr		= 5,
	pt_mom_bits		= 0x1f,
};

/* Mode packet leaves. */
enum pt_mode_leaf {
	pt_mol_exec		= 0x00,
	pt_mol_tsx		= 0x20,
};

/* Mode packet bits. */
enum pt_mode_bit {
	/* mode.exec */
	pt_mob_exec_csl		= 0x01,
	pt_mob_exec_csd		= 0x02,

	/* mode.tsx */
	pt_mob_tsx_intx		= 0x01,
	pt_mob_tsx_abrt		= 0x02,
};

/* The size of the various packets in bytes. */
enum pt_packet_size {
	ptps_pad		= pt_opcs_pad,
	ptps_tnt_8		= pt_opcs_tnt_8,
	ptps_mode		= pt_opcs_mode + pt_pl_mode_size,
	ptps_tsc		= pt_opcs_tsc + pt_pl_tsc_size,
	ptps_psb		= pt_opcs_psb + pt_pl_psb_size,
	ptps_psbend		= pt_opcs_psbend,
	ptps_ovf		= pt_opcs_ovf,
	ptps_pip		= pt_opcs_pip + pt_pl_pip_size,
	ptps_tnt_64		= pt_opcs_tnt_64 + pt_pl_tnt_64_size,
	ptps_cbr		= pt_opcs_cbr + pt_pl_cbr_size,
	ptps_tip_supp		= pt_opcs_tip,
	ptps_tip_upd16		= pt_opcs_tip + pt_pl_ip_upd16_size,
	ptps_tip_upd32		= pt_opcs_tip + pt_pl_ip_upd32_size,
	ptps_tip_sext48		= pt_opcs_tip + pt_pl_ip_sext48_size,
	ptps_tip_pge_supp	= pt_opcs_tip_pge,
	ptps_tip_pge_upd16	= pt_opcs_tip_pge + pt_pl_ip_upd16_size,
	ptps_tip_pge_upd32	= pt_opcs_tip_pge + pt_pl_ip_upd32_size,
	ptps_tip_pge_sext48	= pt_opcs_tip_pge + pt_pl_ip_sext48_size,
	ptps_tip_pgd_supp	= pt_opcs_tip_pgd,
	ptps_tip_pgd_upd16	= pt_opcs_tip_pgd + pt_pl_ip_upd16_size,
	ptps_tip_pgd_upd32	= pt_opcs_tip_pgd + pt_pl_ip_upd32_size,
	ptps_tip_pgd_sext48	= pt_opcs_tip_pgd + pt_pl_ip_sext48_size,
	ptps_fup_supp		= pt_opcs_fup,
	ptps_fup_upd16		= pt_opcs_fup + pt_pl_ip_upd16_size,
	ptps_fup_upd32		= pt_opcs_fup + pt_pl_ip_upd32_size,
	ptps_fup_sext48		= pt_opcs_fup + pt_pl_ip_sext48_size,
};

#endif /* __PT_OPCODE_H__ */
