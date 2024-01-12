% PT_BLK_GET_OFFSET(3)

<!---
 ! Copyright (c) 2016-2024, Intel Corporation
 ! SPDX-License-Identifier: BSD-3-Clause
 !
 ! Redistribution and use in source and binary forms, with or without
 ! modification, are permitted provided that the following conditions are met:
 !
 !  * Redistributions of source code must retain the above copyright notice,
 !    this list of conditions and the following disclaimer.
 !  * Redistributions in binary form must reproduce the above copyright notice,
 !    this list of conditions and the following disclaimer in the documentation
 !    and/or other materials provided with the distribution.
 !  * Neither the name of Intel Corporation nor the names of its contributors
 !    may be used to endorse or promote products derived from this software
 !    without specific prior written permission.
 !
 ! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 ! AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 ! IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ! ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 ! LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 ! CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 ! SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 ! INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 ! CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ! ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 ! POSSIBILITY OF SUCH DAMAGE.
 !-->

# NAME

pt_blk_get_offset, pt_blk_get_sync_offset - get an Intel(R) Processor Trace
block decoder's current/synchronization trace buffer offset


# SYNOPSIS

| **\#include `<intel-pt.h>`**
|
| **int pt_blk_get_offset(const struct pt_block_decoder \**decoder*,**
|                       **uint64_t \**offset*);**
| **int pt_blk_get_sync_offset(const struct pt_block_decoder \**decoder*,**
|                            **uint64_t \**offset*);**

Link with *-lipt*.


# DESCRIPTION

**pt_blk_get_offset**() provides *decoder*'s current position as offset in
bytes from the beginning of *decoder*'s trace buffer in the unsigned integer
variable pointed to by *offset*.

**pt_blk_get_sync_offset**() provides *decoder*'s last synchronization point as
offset in bytes from the beginning of *decoder*'s trace buffer in the unsigned
integer variable pointed to by *offset*.


# RETURN VALUE

Both functions return zero on success or a negative *pt_error_code* enumeration
constant in case of an error.


# ERRORS

pte_invalid
:   The *decoder* or *offset* argument is NULL.

pte_nosync
:   *decoder* has not been synchronized onto the trace stream.  Use
    **pt_blk_sync_forward**(3), **pt_blk_sync_backward**(3), or
    **pt_blk_sync_set**(3) to synchronize *decoder*.


# SEE ALSO

**pt_blk_alloc_decoder**(3), **pt_blk_free_decoder**(3),
**pt_blk_sync_forward**(3), **pt_blk_sync_backward**(3),
**pt_blk_sync_set**(3), **pt_blk_get_config**(3), **pt_blk_time**(3),
**pt_blk_core_bus_ratio**(3), **pt_blk_next**(3)
