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

#include "intel-pt.h"

#include <string.h>
#include <stddef.h>


int pt_cpu_errata(struct pt_errata *errata, const struct pt_cpu *cpu)
{
	if (!errata || !cpu)
		return -pte_invalid;

	memset(errata, 0, sizeof(*errata));

	/* We don't know about others. */
	if (cpu->vendor != pcv_intel)
		return 0;

	switch (cpu->family) {
	case 0x6:
		switch (cpu->model) {
		case 0x3d:
			errata->bdm70 = 1;
			errata->bdm64 = 1;
			break;

		case 0x5e:
			errata->bdm70 = 1;
			errata->skd007 = 1;
			errata->skd022 = 1;
			break;
		}
		break;
	}

	return 0;
}

int pt_config_from_user(struct pt_config *config,
			const struct pt_config *uconfig)
{
	uint8_t *begin, *end;
	size_t size;

	if (!config)
		return -pte_internal;

	if (!uconfig)
		return -pte_invalid;

	size = uconfig->size;
	if (size < offsetof(struct pt_config, decode))
		return -pte_bad_config;

	begin = uconfig->begin;
	end = uconfig->end;

	if (!begin || !end || end < begin)
		return -pte_bad_config;

	/* Ignore fields in the user's configuration we don't know; zero out
	 * fields the user didn't know about.
	 */
	if (sizeof(*config) <= size)
		size = sizeof(*config);
	else
		memset(((uint8_t *) config) + size, 0, sizeof(*config) - size);

	/* Copy (portions of) the user's configuration. */
	memcpy(config, uconfig, size);

	/* We copied user's size - fix it. */
	config->size = size;

	return 0;
}
