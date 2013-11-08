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

#ifndef __PT_PACKET_H__
#define __PT_PACKET_H__

#include "pt_compiler.h"
#include "pt_opcode.h"

#include <stdint.h>

struct pt_decoder;


/* Intel(R) Processor Trace packet types. */
enum pt_packet_type {
	/* 1-byte header packets. */
	ppt_pad			= pt_opc_pad,
	ppt_tip			= pt_opc_tip,
	ppt_tnt_8		= pt_opc_tnt_8 | 0xFE,
	ppt_tip_pge		= pt_opc_tip_pge,
	ppt_tip_pgd		= pt_opc_tip_pgd,
	ppt_fup			= pt_opc_fup,
	ppt_mode		= pt_opc_mode,
	ppt_tsc			= pt_opc_tsc,

	/* 2-byte header packets. */
	ppt_psb			= pt_opc_ext << 8 | pt_ext_psb,
	ppt_tnt_64		= pt_opc_ext << 8 | pt_ext_tnt_64,
	ppt_pip			= pt_opc_ext << 8 | pt_ext_pip,
	ppt_ovf			= pt_opc_ext << 8 | pt_ext_ovf,
	ppt_psbend		= pt_opc_ext << 8 | pt_ext_psbend,
	ppt_cbr			= pt_opc_ext << 8 | pt_ext_cbr,

	/* A packet decodable by the optional decoder callback. */
	ppt_unknown		= 0x7ffffffe,

	/* An invalid packet. */
	ppt_invalid		= 0x7fffffff
};

/* A TNT-8 or TNT-64 packet. */
struct pt_packet_tnt {
	/* TNT payload bit size. */
	uint8_t bit_size;

	/* TNT payload excluding stop bit. */
	uint64_t payload;
};

/* A packet with IP payload. */
struct pt_packet_ip {
	/* IP compression. */
	enum pt_ip_compression ipc;

	/* Zero-extended payload ip. */
	uint64_t ip;
};

/* A mode.exec packet. */
struct pt_packet_mode_exec {
	/* The mode.exec payload bits. */
	uint32_t csl:1;
	uint32_t csd:1;
};

static inline enum pt_exec_mode
pt_get_exec_mode(const struct pt_packet_mode_exec *packet)
{
	if (packet->csl)
		return packet->csd ? ptem_unknown : ptem_64bit;
	else
		return packet->csd ? ptem_32bit : ptem_16bit;
}

/* A mode.tsx packet. */
struct pt_packet_mode_tsx {
	/* The mode.tsx payload bits. */
	uint32_t intx:1;
	uint32_t abrt:1;
};

/* A mode packet. */
struct pt_packet_mode {
	/* Mode leaf. */
	enum pt_mode_leaf leaf;

	/* Mode bits. */
	union {
		/* Packet: mode.exec. */
		struct pt_packet_mode_exec exec;

		/* Packet: mode.tsx. */
		struct pt_packet_mode_tsx tsx;
	} bits;
};

/* A PIP packet. */
struct pt_packet_pip {
	/* The CR3 value. */
	uint64_t cr3;
};

/* A TSC packet. */
struct pt_packet_tsc {
	/* The TSC value. */
	uint64_t tsc;
};

/* A CBR packet. */
struct pt_packet_cbr {
	/* The core/bus cycle ratio. */
	uint8_t ratio;
};

/* An unknown packet decodable by the optional decoder callback. */
struct pt_packet_unknown {
	/* Pointer to the raw packet bytes. */
	const uint8_t *packet;

	/* Optional pointer to a user-defined structure. */
	void *priv;
};

/* An Intel(R) Processor Trace packet. */
struct pt_packet {
	/* Type of the packet, used to indicate which sub-struct to use. */
	enum pt_packet_type type;

	/* Size of the packet, including opcode and payload. */
	uint8_t size;

	/* Packet specific data. */
	union {
		/* Packets: pad, ovf, psb, psbend - no payload. */

		/* Packet: tnt-8, tnt-64. */
		struct pt_packet_tnt tnt;

		/* Packet: tip, fup, tip.pge, tip.pgd. */
		struct pt_packet_ip ip;

		/* Packet: mode. */
		struct pt_packet_mode mode;

		/* Packet: pip. */
		struct pt_packet_pip pip;

		/* Packet: tsc. */
		struct pt_packet_tsc tsc;

		/* Packet: cbr. */
		struct pt_packet_cbr cbr;

		/* Packet: unknown. */
		struct pt_packet_unknown unknown;
	} payload;
};


/* Decode the next packet.
 *
 * Decodes the packet at @decoder's current position into @packet.
 *
 * Returns the number of bytes consumed on success.
 *
 * Returns -pte_invalid if no decoder or no packet is given.
 * Returns -pte_nosync if the decoder is out of sync.
 * Returns -pte_eos if the decoder reached the end of the PT buffer.
 * Returns -pte_bad_opc if the packet is unknown to the decoder.
 */
extern pt_export int pt_decode(struct pt_packet *packet,
			       struct pt_decoder *decoder);

#endif /* __PT_PACKET_H__ */
