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

#ifndef __PT_CONFIG_H__
#define __PT_CONFIG_H__

#include "pt_compiler.h"

#include <stdint.h>
#include <stdlib.h>

struct pt_decoder;
struct pt_packet;


/* A cpu vendor. */
enum pt_cpu_vendor {
	pcv_unknown,
	pcv_intel
};

/* A cpu identifier. */
struct pt_cpu {
	/* The cpu vendor. */
	enum pt_cpu_vendor vendor;

	/* The cpu family. */
	uint16_t family;

	/* The cpu model. */
	uint8_t model;

	/* The stepping. */
	uint8_t stepping;
};

/* A Intel(R) Processor Trace configuration.
 *
 * The configuration is used for allocating a Intel(R) Processor Trace decoder.
 */
struct pt_config {
	/* The size of the config structure in bytes. */
	size_t size;

	/* The trace buffer begin and end addresses. */
	uint8_t *begin;
	uint8_t *end;

	/* An optional callback function for handling unknown packets.
	 *
	 * The callback is called for any unknown opcode.
	 *
	 * It shall decode the packet at @decoder's current position into
	 * @packet.

	 * It shall return the number of bytes read upon success.
	 * It shall return a negative pt_error_code otherwise.
	 */
	int (*decode)(struct pt_packet *packet,
		      const struct pt_decoder *decoder);

	/* The cpu on which PT has been recorded. */
	struct pt_cpu cpu;
};


/* Configure the Intel(R) Processor Trace library.
 *
 * Collects information on the current system necessary for PT decoding and
 * stores it into @config.
 *
 * This function should be executed on the system on which PT is collected.
 * The resulting PT configuration should then be used for allocating PT
 * decoders.
 *
 * Returns 0 on success, a negative error code otherwise.
 * Returns -pte_invalid if @config is NULL.
 */
extern pt_export int pt_configure(struct pt_config *config);

#endif /* __PT_CONFIG_H__ */
