/*
 * Copyright (c) 2014, Intel Corporation
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

#include "pt_time.h"

#include "intel-pt.h"

#include <string.h>


void pt_time_init(struct pt_time *time)
{
	if (!time)
		return;

	memset(time, 0, sizeof(*time));
}

int pt_time_query_tsc(uint64_t *tsc, const struct pt_time *time)
{
	if (!tsc || !time)
		return -pte_internal;

	*tsc = time->tsc;

	return 0;
}

int pt_time_query_cbr(uint32_t *cbr, const struct pt_time *time)
{
	if (!cbr || !time)
		return -pte_internal;

	*cbr = time->cbr;

	return 0;
}

int pt_time_update_tsc(struct pt_time *time,
		       const struct pt_packet_tsc *packet,
		       const struct pt_config *config)
{
	if (!time || !packet)
		return -pte_internal;

	time->tsc = packet->tsc;

	return 0;
}

int pt_time_update_cbr(struct pt_time *time,
		       const struct pt_packet_cbr *packet,
		       const struct pt_config *config)
{
	if (!time || !packet)
		return -pte_internal;

	/* We store the CBR even in case of errors so future queries
	 * get the correct information that we do not know the current
	 * core:bus ratio.
	 */
	time->cbr = packet->ratio;

	if (!packet->ratio)
		return -pte_bad_packet;

	return 0;
}
