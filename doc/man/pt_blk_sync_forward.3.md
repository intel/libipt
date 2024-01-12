% PT_BLK_SYNC_FORWARD(3)

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

pt_blk_sync_forward, pt_blk_sync_backward, pt_blk_sync_set - synchronize an
Intel(R) Processor Trace block decoder


# SYNOPSIS

| **\#include `<intel-pt.h>`**
|
| **int pt_blk_sync_forward(struct pt_block_decoder \**decoder*);**
| **int pt_blk_sync_backward(struct pt_block_decoder \**decoder*);**
| **int pt_blk_sync_set(struct pt_block_decoder \**decoder*,**
|                     **uint64_t *offset*);**

Link with *-lipt*.


# DESCRIPTION

These functions synchronize an Intel Processor Trace (Intel PT) block decoder
pointed to by *decoder* onto the trace stream in *decoder*'s trace buffer.

They search for a Packet Stream Boundary (PSB) packet in the trace stream and,
if successful, set *decoder*'s current position and synchronization position to
that packet and start processing packets.  For synchronization to be
successfull, there must be a full PSB+ header in the trace stream.

**pt_blk_sync_forward**() searches in forward direction from *decoder*'s
current position towards the end of the trace buffer.  If *decoder* has been
newly allocated and has not been synchronized yet, the search starts from the
beginning of the trace.

**pt_blk_sync_backward**() searches in backward direction from *decoder*'s
current position towards the beginning of the trace buffer.  If *decoder* has
been newly allocated and has not been synchronized yet, the search starts from
the end of the trace.

**pt_blk_sync_set**() searches at *offset* bytes from the beginning of its
trace buffer.


# RETURN VALUE

All synchronization functions return zero or a positive value on success or a
negative *pt_error_code* enumeration constant in case of an error.

On success, a bit-vector of *pt_status_flag* enumeration constants is returned.
The *pt_status_flag* enumeration is declared as:

~~~{.c}
/** Decoder status flags. */
enum pt_status_flag {
    /** There is an event pending. */
    pts_event_pending    = 1 << 0,

    /** The address has been suppressed. */
    pts_ip_suppressed    = 1 << 1,

    /** There is no more trace data available. */
    pts_eos              = 1 << 2
};
~~~

The *pts_event_pending* flag indicates that one or more events are pending.  Use
**pt_blk_event**(3) to process pending events before calling **pt_blk_next**(3).

The *pt_eos* flag indicates that the information contained in the Intel PT
stream has been consumed.  Calls to **pt_blk_next**() will provide blocks for
instructions as long as the instruction's addresses can be determined without
further trace.


# ERRORS

pte_invalid
:   The *decoder* argument is NULL.

pte_eos
:   There is no (further) PSB+ header in the trace stream
    (**pt_blk_sync_forward**() and **pt_blk_sync_backward**()) or at *offset*
    bytes into the trace buffer (**pt_blk_sync_set**()).

pte_nosync
:   There is no PSB packet at *offset* bytes from the beginning of the trace
    (**pt_blk_sync_set**() only).

pte_bad_opc
:   The decoder encountered an unsupported Intel PT packet opcode.

pte_bad_packet
:   The decoder encountered an unsupported Intel PT packet payload.


# EXAMPLE

The following example re-synchronizes an Intel PT block decoder after decode
errors:

~~~{.c}
int foo(struct pt_block_decoder *decoder) {
    for (;;) {
        int errcode;

        errcode = pt_blk_sync_forward(decoder);
        if (errcode < 0)
            return errcode;

        do {
            errcode = decode(decoder);
        } while (errcode >= 0);
    }
}
~~~


# SEE ALSO

**pt_blk_alloc_decoder**(3), **pt_blk_free_decoder**(3),
**pt_blk_get_offset**(3), **pt_blk_get_sync_offset**(3),
**pt_blk_get_config**(3), **pt_blk_time**(3), **pt_blk_core_bus_ratio**(3),
**pt_blk_next**(3), **pt_blk_event**(3)
