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

#ifndef __PT_PACKET_DECODE_H__
#define __PT_PACKET_DECODE_H__

struct pt_packet;
struct pt_decoder;


/* Decoder functions for the packet decoder. */
extern int pt_pkt_decode_unknown(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_pad(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_psb(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tip(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tnt_8(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tnt_64(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tip_pge(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tip_pgd(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_fup(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_pip(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_ovf(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_mode(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_psbend(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_tsc(struct pt_packet *, const struct pt_decoder *);
extern int pt_pkt_decode_cbr(struct pt_packet *, const struct pt_decoder *);

/* Decoder functions for the query decoder (tracing context). */
extern int pt_qry_decode_unknown(struct pt_decoder *);
extern int pt_qry_decode_pad(struct pt_decoder *);
extern int pt_qry_decode_psb(struct pt_decoder *);
extern int pt_qry_decode_tip(struct pt_decoder *);
extern int pt_qry_decode_tnt_8(struct pt_decoder *);
extern int pt_qry_decode_tnt_64(struct pt_decoder *);
extern int pt_qry_decode_tip_pge(struct pt_decoder *);
extern int pt_qry_decode_tip_pgd(struct pt_decoder *);
extern int pt_qry_decode_fup(struct pt_decoder *);
extern int pt_qry_decode_pip(struct pt_decoder *);
extern int pt_qry_decode_ovf(struct pt_decoder *);
extern int pt_qry_decode_mode(struct pt_decoder *);
extern int pt_qry_decode_psbend(struct pt_decoder *);
extern int pt_qry_decode_tsc(struct pt_decoder *);
extern int pt_qry_decode_cbr(struct pt_decoder *);

/* Decoder functions for the query decoder (header context). */
extern int pt_qry_header_psb(struct pt_decoder *);
extern int pt_qry_header_fup(struct pt_decoder *);
extern int pt_qry_header_pip(struct pt_decoder *);
extern int pt_qry_header_mode(struct pt_decoder *);

#endif /* __PT_PACKET_DECODE_H__ */
