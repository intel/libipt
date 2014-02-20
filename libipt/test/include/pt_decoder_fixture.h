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

#ifndef __PT_DECODER_FIXTURE_H__
#define __PT_DECODER_FIXTURE_H__

#include "pt_check.h"

#include "pt_packet_decode.h"
#include "pt_last_ip.h"
#include "pt_tnt_cache.h"
#include "pt_encoder.h"

#include "intel-pt.h"


/* An Intel(R) Processor Trace decoder unit test fixture. */
struct pt_decoder_fixture_s {
	/* The trace buffer. */
	uint8_t buffer[1024];

	/* The configuration under test. */
	struct pt_config config;

	/* A encoder and decoder for the above configuration. */
	struct pt_encoder encoder;
	struct pt_decoder *decoder;

	/* For testing last-ip changes. */
	struct pt_last_ip last_ip;

	/* For testing tnt cache changes. */
	struct pt_tnt_cache tnt;
};

/* The highest possible address. */
static const uint64_t pt_dfix_max_ip = (1ull << 47) - 1;

/* A sign-extended address. */
static const uint64_t pt_dfix_sext_ip = 0xffffff00ff00ff00ull;

/* An invalid address. */
static const uint64_t pt_dfix_bad_ip = (1ull << 62) - 1;

/* The highest possible cr3 value. */
static const uint64_t pt_dfix_max_cr3 = ((1ull << 47) - 1) & ~0x1f;

/* An invalid cr3 value. */
static const uint64_t pt_dfix_bad_cr3 = (1ull << 62) - 1;

/* A bad value pattern.  */
static const uint64_t pt_dfix_bad_pattern = 0xccccccccccccccccull;


extern struct pt_decoder_fixture_s pt_decoder_fixture;

/* Setup the standard testing configuration. */
extern void pt_dfix_setup_config(struct pt_config *);

/* Setup for standard decoding. */
extern void pt_dfix_setup_standard(void);

/* Setup for standard decoding but do not synchronize the decoder. */
extern void pt_dfix_setup_nosync(void);

/* Tear down the fixture. */
extern void pt_teardown_decoder_fixture(void);

/* Check the last-ip in decoder and fixture for equality. */
extern void pt_dfix_check_last_ip(const char *file, int line);

#define ck_last_ip() pt_dfix_check_last_ip(__FILE__, __LINE__)

/* Check the tnt cache in decoder and fixture for equality. */
extern void pt_dfix_check_tnt_cache(const char *file, int line);

#define ck_tnt_cache() pt_dfix_check_tnt_cache(__FILE__, __LINE__)

/* Add a decoder fixture to a test case. */
static inline void add_dfix(TCase *tcase, void (*setup)(void))
{
	tcase_add_checked_fixture(tcase, setup, pt_teardown_decoder_fixture);
}


/* A decoder fixture descriptor. */
struct dfix_desc {
	/* The variant name. */
	const char *name;

	/* The fixture setup function. */
	SFun setup;
};

/* Standard fixture descriptors. */
extern struct dfix_desc dfix_standard;
extern struct dfix_desc dfix_nosync;

/* A test case descriptor. */
struct tcase_desc {
	/* The test base name. */
	const char *name;

	/* The function adding tests to the test case.
	 *
	 * We use a function to get the test case name right.
	 */
	void (*add_tests)(TCase *);
};

/* Add a new test case based on dfix and tcase descriptors. */
extern void pt_add_tcase(Suite *,
			 const struct tcase_desc *,
			 const struct dfix_desc *);

/* Add a series of new test cases based on dfix and tcase descriptors. */
static inline void pt_add_tcase_series(Suite *suite,
				       const struct tcase_desc *td,
				       const struct dfix_desc **dd)
{
	for (; *dd; ++dd)
		pt_add_tcase(suite, td, *dd);
}


/* Synchronize the decoder at the beginning of the trace stream, avoiding the
 * initial PSB header.
 */
static inline void pt_sync_decoder(struct pt_decoder *decoder)
{
	(void) pt_fetch_decoder(decoder);
}

/*
 * The below encoding functions operate on an encoder.
 * They fail_if the buffer would overflow.
 * They return the position after the encoded packet.
 */

/* Encode a Padding (pad) packet. */
extern void *check_encode_pad(struct pt_encoder *);

/* Encode a Packet Stream Boundary (psb) packet. */
extern void *check_encode_psb(struct pt_encoder *);

/* Encode an End PSB (psbend) packet. */
extern void *check_encode_psbend(struct pt_encoder *);

/* Encode a Target Instruction Pointer (tip) packet. */
extern void *check_encode_tip(struct pt_encoder *, uint64_t ip,
				  enum pt_ip_compression ipc);

/* Encode a Taken Not Taken (tnt) packet - 8-bit version. */
extern void *check_encode_tnt_8(struct pt_encoder *, uint8_t tnt, int size);

/* Encode a Taken Not Taken (tnt) packet - 64-bit version. */
extern void *check_encode_tnt_64(struct pt_encoder *, uint64_t tnt, int size);

/* Encode a Packet Generation Enable (tip.pge) packet. */
extern void *check_encode_tip_pge(struct pt_encoder *, uint64_t ip,
				  enum pt_ip_compression ipc);

/* Encode a Packet Generation Disable (tip.pgd) packet. */
extern void *check_encode_tip_pgd(struct pt_encoder *, uint64_t ip,
				  enum pt_ip_compression ipc);

/* Encode a Flow Update Packet (fup). */
extern void *check_encode_fup(struct pt_encoder *, uint64_t ip,
				  enum pt_ip_compression ipc);

/* Encode a Paging Information Packet (pip). */
extern void *check_encode_pip(struct pt_encoder *, uint64_t);

/* Encode a Overflow Packet (ovf). */
extern void *check_encode_ovf(struct pt_encoder *);

/* Encode a Mode Exec Packet (mode.exec). */
extern void *check_encode_mode_exec(struct pt_encoder *, enum pt_exec_mode);

/* Encode a Mode Tsx Packet (mode.tsx). */
extern void *check_encode_mode_tsx(struct pt_encoder *, uint8_t);

/* Encode a Time Stamp Counter (tsc) packet. */
extern void *check_encode_tsc(struct pt_encoder *, uint64_t);

/* Encode a Core Bus Ratio (cbr) packet. */
extern void *check_encode_cbr(struct pt_encoder *, uint8_t);

#endif /* __PT_DECODER_FIXTURE_H__ */
