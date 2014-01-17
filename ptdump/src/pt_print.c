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

#include "pt_print.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>


/* Sign-extend a uint64_t value. */
static uint64_t sext(uint64_t val, uint8_t sign)
{
	int64_t sval;
	uint8_t shc;

	sval = (int64_t) val;
	shc = 64 - sign;

	sval <<= shc;
	sval >>= shc;

	return (uint64_t) sval;
}

static int strprint(char *str, uint64_t size, const char *format, ...)
{
	int ret;
	va_list ap;

	va_start(ap, format);
	ret = vsnprintf(str, (size_t)size, format, ap);
	va_end(ap);

	if (ret < 0)
		ret = -pte_internal;

	return ret;
}

const char *pt_print_packet_type_str(const struct pt_packet *packet)
{
	if (!packet)
		return NULL;

	switch (packet->type) {
	case ppt_psb:
		return "psb";
	case ppt_psbend:
		return "psbend";
	case ppt_pad:
		return "pad";
	case ppt_ovf:
		return "ovf";
	case ppt_unknown:
		return "(unknown)";
	case ppt_invalid:
		return "(invalid)";
	case ppt_tip:
		return "tip";
	case ppt_tip_pge:
		return "tip.pge";
	case ppt_tip_pgd:
		return "tip.pgd";
	case ppt_fup:
		return "fup";
	case ppt_tnt_8:
		return "tnt8";
	case ppt_tnt_64:
		return "tnt64";
	case ppt_pip:
		return "pip";
	case ppt_mode:
		switch (packet->payload.mode.leaf) {
		case pt_mol_exec:
			return "mode.exec";
		case pt_mol_tsx:
			return "mode.tsx";
		}
		break;
	case ppt_tsc:
		return "tsc";
	case ppt_cbr:
		return "cbr";
	}
	return NULL;
}

const char *pt_print_exec_mode_str(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_16bit:
		return "16-bit mode";
	case ptem_32bit:
		return "32-bit mode";
	case ptem_64bit:
		return "64-bit mode";
	case ptem_unknown:
		return "<unknown mode>";
	}
	return NULL;
}

int pt_print_strprint_ip_packet(char *str, uint64_t size,
				const struct pt_packet_ip *packet)
{
	enum pt_ip_compression ipc;
	uint64_t ip;

	if (!str || !packet)
		return -pte_invalid;

	ipc = packet->ipc;
	ip = packet->ip;

	switch (ipc) {
	case pt_ipc_suppressed:
		if (ip)
			return -pte_bad_packet;

		return strprint(str, size,
				"%d: 0x????????????????", ipc);
	case pt_ipc_update_16:
		if (ip & ~0xffffull)
			return -pte_bad_packet;

		return strprint(str, size,
				"%d: 0x????????????%04" PRIx64, ipc, ip);
	case pt_ipc_update_32:
		if (ip & ~0xffffffffull)
			return -pte_bad_packet;

		return strprint(str, size,
				"%d: 0x????????%08" PRIx64, ipc, ip);
	case pt_ipc_sext_48:
		if (ip & ~0xffffffffffffull)
			return -pte_bad_packet;

		ip = sext(ip, 48);

		return strprint(str, size,
				"%d: 0x%016" PRIx64, ipc, ip);
	}

	return -pte_bad_packet;
}

int pt_print_fill_payload_str(char *str, uint64_t size,
			      const struct pt_packet *packet)
{
	int nchar = 0;

	if (!str || !packet || size == 0)
		return -pte_invalid;

	switch (packet->type) {
	case ppt_tip:
	case ppt_tip_pge:
	case ppt_tip_pgd:
	case ppt_fup:
		nchar = pt_print_strprint_ip_packet(str, size,
					   &packet->payload.ip);
		goto known;

	case ppt_tnt_8:
	case ppt_tnt_64: {
		int ret;
		uint8_t bits = packet->payload.tnt.bit_size;
		uint64_t tnt = packet->payload.tnt.payload;

		for (; bits > 0; --bits) {
			uint64_t mask = 1ull << (bits - 1);

			if ((uint64_t)nchar >= size)
				break;

			ret = strprint(str + nchar, size - nchar,
				       (tnt & mask) ? "!" : ".");
			if (ret < 0)
				return -pte_internal;

			nchar += ret;
		}
	}
		goto known;

	case ppt_mode:
		switch (packet->payload.mode.leaf) {
		case pt_mol_exec: {
			const struct pt_packet_mode_exec *execpacket;
			enum pt_exec_mode execmode;

			execpacket = &packet->payload.mode.bits.exec;
			execmode = pt_get_exec_mode(execpacket);
			nchar = strprint(str, size,
					 "cs.d=%u, cs.l=%u (%s)",
					 execpacket->csd,
					 execpacket->csl,
					 pt_print_exec_mode_str(execmode));
		}
			goto known;

		case pt_mol_tsx:
			nchar = strprint(str, size,
					 "intx=%u, abort=%u",
					 packet->payload.mode.bits.tsx.intx,
					 packet->payload.mode.bits.tsx.abrt);
			goto known;
		}
		goto unknown;

	case ppt_pip:
		nchar = strprint(str, size, "0x%016" PRIx64,
				 packet->payload.pip.cr3);
		goto known;

	case ppt_tsc:
		nchar = strprint(str, size, "0x%016" PRIx64,
				 packet->payload.tsc.tsc);
		goto known;

	case ppt_cbr:
		nchar = strprint(str, size, "%u", packet->payload.cbr.ratio);
		goto known;

	case ppt_psb:
	case ppt_pad:
	case ppt_ovf:
	case ppt_psbend:
	case ppt_unknown:
	case ppt_invalid:
		/* No payload to be printed. */
		goto known;
	}

unknown:
	return -pte_bad_opc;

known:
	if (nchar < 0)
		return nchar;

	if ((uint64_t)nchar >= size)
		nchar = (int)size - 1;

	*(str + nchar) = '\0';

	return nchar;
}
