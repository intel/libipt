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

#ifndef __PT_PRINT_H__
#define __PT_PRINT_H__

#include "intel-pt.h"

#include <stdint.h>

struct pt_packet;
struct pt_packet_ip;


/* Print sizes for strings returned by pt_print_*() functions,
 * including the zero-termination.
 *
 * This can be used to pre-allocate reusable string buffers.
 */
enum pt_print_size {
	pps_packet_type	= 10,
	pps_payload	= 48,
	pps_exec_mode	= 15,
	pps_ip_payload	= 22
};


/* Get a textual representation of an Intel(R) Processor Trace
 * packet type.
 *
 * Generates a string representation of the packet type from the
 * passed in @packet.
 *
 * Returns const string on success.
 * Returns NULL on error or if @packet is NULL.
 */
extern const char *pt_print_packet_type_str(const struct pt_packet *packet);


/* Get a human readable interpretation of an Intel(R) Processor Trace
 * packet payload.
 *
 * Interprets the payload of the passed-in @packet and fills the passed-in
 * string @str, which has a capacity of @size, with a human-readable
 * representation of the packet payload. If @size is too low for all characters
 * to be printed, the output will be truncated.
 *
 * Returns number of bytes printed (excluding the terminating zero,
 * maximum @size) on success; or a negative error code otherwise.
 * Returns -pte_invalid if @str or @packet is NULL or @size is 0.
 * Returns -pte_internal on any output errors.
 * Returns -pte_bad_opc if the packet type is not recognized.
 * Returns -pte_bad_packet on sanity check errors of the packet payload.
 */
extern int pt_print_fill_payload_str(char *str, uint64_t size,
				     const struct pt_packet *packet);


/* Get a textual representation for the execution mode enum.
 *
 * Generates a string representation of the passed in @mode.
 *
 * Returns const string on success.
 * Returns NULL on error.
 */
extern const char *pt_print_exec_mode_str(enum pt_exec_mode mode);


/* Get a human readable interpretation of an Intel(R) Processor Trace
 * packet with IP payload.
 *
 * Interprets the payload of the passed-in @packet and fills the passed-in
 * string @str, which has a capacity of @size, with a human-readable
 * representation of the packet payload. If @size is too low for all characters
 * to be printed, the output will be truncated.
 *
 * Returns number of bytes printed (excluding the terminating zero,
 * maximum @size) on success; or a negative error code otherwise.
 * Returns -pte_invalid if @str or @packet is NULL or @size is 0.
 * Returns -pte_internal on any output errors.
 * Returns -pte_bad_packet on sanity check errors of the packet payload.
 */
extern int pt_print_strprint_ip_packet(char *str, uint64_t size,
				       const struct pt_packet_ip *packet);


#endif /* __PT_PRINT_H__ */
