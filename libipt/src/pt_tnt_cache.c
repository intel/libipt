/*
 * Copyright (c) 2013-2022, Intel Corporation
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

#include "pt_tnt_cache.h"

#include "intel-pt.h"


void pt_tnt_cache_init(struct pt_tnt_cache *cache)
{
	if (!cache)
		return;

	cache->tnt = 0ull;
	cache->index = 0ull;
}

int pt_tnt_cache_is_empty(const struct pt_tnt_cache *cache)
{
	if (!cache)
		return -pte_invalid;

	return cache->index == 0;
}

int pt_tnt_cache_query(struct pt_tnt_cache *cache)
{
	int taken;

	if (!cache)
		return -pte_invalid;

	if (!cache->index)
		return -pte_bad_query;

	taken = (cache->tnt & cache->index) != 0;
	cache->index >>= 1;

	return taken;
}

int pt_tnt_cache_add(struct pt_tnt_cache *cache, uint64_t tnt, uint8_t size)
{
	uint64_t index;

	if (!cache)
		return -pte_invalid;

	if (!size)
		return 0;

	index = cache->index;
	if (index)
		index <<= size;
	else
		index = 1ull << (size - 1);

	if (!index)
		return -pte_overflow;

	cache->index = index;
	cache->tnt <<= size;
	cache->tnt |= tnt & ((1ull << size) - 1);

	return 0;
}
