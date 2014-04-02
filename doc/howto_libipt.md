Decoding Intel(R) Processor Trace Using libipt {#libipt}
========================================================

<!---
 ! Copyright (c) 2013-2014, Intel Corporation
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

This chapter describes how to use libipt for various tasks around Intel
Processor Trace (PT).  For code examples, refer to the sample tools that are
contained in the source tree:

  * *ptdump*    A packet dumper example.
  * *ptxed*     A control-flow reconstruction example.
  * *pttc*      A packet encoder example.


For an overview of PT and for detailed information about the PT specification,
refer to the respective chapter in the Software Developer's Manual.


## Introduction

The libipt decoder library provides multiple layers of abstraction ranging from
packet encoding and decoding to full execution flow reconstruction.  The layers
are organized as follows:

  * *packets*               This layer deals with raw PT packets.

  * *events*                This layer deals with packet combinations that
                            encode higher-level events.

  * *instruction flow*      This layer deals with the execution flow on the
                            instruction level.


Each layer provides its own encoder or decoder struct plus a set of functions
for allocating and freeing encoder or decoder objects and for synchronizing
decoders onto the PT stream.  Function names are prefixed with `pt_<lyr>_` where
`<lyr>` is an abbreviation of the layer name.  The following abbreviations are
used:

  * *enc*     Packet encoding (packet layer).
  * *pkt*     Packet decoding (packet layer).
  * *qry*     Event (or query) layer.
  * *insn*    Instruction flow layer.


Here is some generic example code for working with decoders:

~~~{.c}
    struct pt_<layer>_decoder *decoder;
    struct pt_config config;
    int errcode;

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = <pt buffer begin>;
    config.end = <pt buffer end>;
    config.cpu = <cpu identifier>;
    config...

    decoder = pt_<lyr>_alloc_decoder(&config);
    if (!decoder)
        <handle error>(errcode);

    errcode = pt_<lyr>_sync_<where>(decoder);
    if (errcode < 0)
        <handle error>(errcode);

    <use decoder>(decoder);

    pt_<lyr>_free_decoder(decoder);
~~~

First, configure the decoder.  As a minimum, the size of the config struct and
the `begin` and `end` of the buffer containing the PT data need to be set.
Configuration options details will be discussed later in this chapter.  In the
case of packet encoding, this is the begin and end address of the pre-allocated
buffer, into which PT packets shall be written.

Next, allocate a decoder object for the layer you are interested in.  A return
value of NULL indicates an error.  There is no further information available on
the exact error condition.  Most of the time, however, the error is the result
of an incomplete or inconsistent configuration.

Before the decoder can be used, it needs to be synchronized onto the PT stream
specified in the configuration.  The only exception to this is the packet
encoder, which is implicitly synchronized onto the beginning of the PT buffer.

Depending on the type of decoder, one or more synchronization options are
available.

  * `pt_<lyr>_sync_forward()`     Synchronize onto the next PSB in forward
                                  direction (or the first PSB if not yet
                                  synchronized).

  * `pt_<lyr>_sync_backward()`    Synchronize onto the next PSB in backward
                                  direction (or the last PSB if not yet
                                  synchronized).

  * `pt_<lyr>_sync_set()`         Set the synchronization position to a
                                  user-defined location in the PT stream.
                                  There is no check whether the specified
                                  location makes sense or is valid.


After synchronizing, the decoder can be used.  While decoding, the decoder
stores the location of the last PSB it encountered during normal decode.
Subsequent calls to pt_<lyr>_sync_forward() will start searching from that
location.  This is useful for re-synchronizing onto the PT stream in case of
errors.  An example of a typical decode loop is given below:

~~~{.c}
    for (;;) {
        int errcode;

        errcode = <use decoder>(decoder);
        if (errcode >= 0)
            continue;

        if (errcode == -pte_eos)
            return;

        <report error>(errcode);

        do {
            errcode = pt_<lyr>_sync_forward(decoder);

            if (errcode == -pte_eos)
                return;
        } while (errcode < 0);
    }
~~~

You can get the current decoder position as offset into the PT buffer via:

    pt_<lyr>_get_offset()


You can get the position of the last synchronization point as offset into the PT
buffer via:

    pt_<lyr>_get_sync_offset()


Each layer will be discussed in detail below.  In the remainder of this section,
general functionality will be considered.


### Version

You can query the library version using:

  * `pt_library_version()`


This function returns a version structure that can be used for compatibility
checks or simply for reporting the version of the decoder library.


### Errors

The library uses a single error enum for all layers.

  * `enum pt_error_code`      An enumeration of encode and decode errors.


Errors are typically represented as negative pt_error_code enumeration constants
and returned as an int.  The library provides two functions for dealing with
errors:

  * `pt_errcode()`            Translate an int return value into a pt_error_code
                              enumeration constant.

  * `pt_errstr()`             Returns a human-readable error string.


Not all errors may occur on every layer.  Every API function specifies the
errors it may return.


### Configuration

Every encoder or decoder allocation function requires a configuration argument.
Some of its fields have already been discussed in the example above.  Refer to
the `intel-pt.h` header for detailed and up-to-date documentation of each field.

As a minimum, the `size` field needs to be set to `sizeof(struct pt_config)` and
`begin` and `end` need to be set to the PT buffer to use.

The size is used for detecting library version mismatches and to provide
backwards compatibility.  Without the proper `size`, decoder allocation will
fail.

Although not strictly required, it is recommended to also set the `cpu` field to
the processor, on which PT has been collected (for decoders), or for which PT
shall be generated (for encoders).  This allows implementing processor-specific
behavior such as erratum workarounds.


## The Packet Layer

This layer deals with PT packet encoding and decoding.  It can further be split
into three sub-layers: opcodes, encoding, and decoding.


### Opcodes

The opcodes layer provides enumerations for all the bits necessary for PT
encoding and decoding.  The enumeration constants can be used without linking to
the decoder library.  There is no encoder or decoder struct associated with this
layer.  See the intel-pt.h header file for details.


### Packet Encoding

The packet encoding layer provides support for encoding PT packet-by-packet.
Start by configuring and allocating a `pt_packet_encoder` as shown below:

~~~{.c}
    struct pt_encoder *encoder;
    struct pt_config config;
    int errcode;

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = <pt buffer begin>;
    config.end = <pt buffer end>;
    config.cpu = <cpu identifier>;

    encoder = pt_alloc_encoder(&config);
    if (!encoder)
        <handle error>(errcode);
~~~

For packet encoding, only the mandatory config fields need to be filled in.

The allocated encoder object will be implicitly synchronized onto the beginning
of the PT buffer.  You may change the encoder's position at any time by calling
`pt_enc_sync_set()` with the desired buffer offset.

Next, fill in a `pt_packet` object with details about the packet to be encoded.
You do not need to fill in the `size` field.  The needed size is computed by the
encoder.  There is no consistency check with the size specified in the packet
object.  The following example encodes a TIP packet:

~~~{.c}
    struct pt_packet_encoder *encoder = ...;
    struct pt_packet packet;
    int errcode;

    packet.type = ppt_tip;
    packet.payload.ip.ipc = pt_ipc_update_16;
    packet.payload.ip.ip = <ip>;
~~~

For IP packets, for example FUP or TIP.PGE, there is no need to mask out bits in
the `ip` field that will not be encoded in the packet due to the specified IP
compression in the `ipc` field.  The encoder will ignore them.

There are no consistency checks whether the specified IP compression in the
`ipc` field is allowed in the current context or whether decode will result in
the full IP specified in the `ip` field.

Once the packet object has been filled, it can be handed over to the encoder as
shown here:

~~~{.c}
    errcode = pt_enc_next(encoder, &packet);
    if (errcode < 0)
        <handle error>(errcode);
~~~

The encoder will encode the packet, write it into the PT buffer, and advance its
position to the next byte after the packet.  On a successful encode, it will
return the number of bytes that have been written.  In case of errors, nothing
will be written and the encoder returns a negative error code.


### Packet Decoding

The packet decoding layer provides support for decoding PT packet-by-packet.
Start by configuring and allocating a `pt_packet_decoder` as shown
here:

~~~{.c}
    struct pt_packet_decoder *decoder;
    struct pt_config config;
    int errcode;

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = <pt buffer begin>;
    config.end = <pt buffer end>;
    config.cpu = <cpu identifier>;
    config.decode.callback = <decode function>;
    config.decode.context = <decode context>;

    decoder = pt_pkt_alloc_decoder(&config);
    if (!decoder)
        <handle error>(errcode);
~~~

For packet decoding, an optional decode callback function may be specified in
addition to the mandatory config fields.  If specified, the callback function
will be called for packets the decoder does not know about.  If there is no
decode callback specified, the decoder will return `-pte_bad_opc`.  In addition
to the callback function pointer, an optional pointer to user-defined context
information can be specified.  This context will be passed to the decode
callback function.

Before the decoder can be used, it needs to be synchronized onto the PT stream.
Packet decoders offer three synchronization functions.  To iterate over
synchronization points in the PT stream in forward or backward direction, use
one of the following two functions respectively:

    pt_pkt_sync_forward()
    pt_pkt_sync_backward()


To manually synchronize the decoder at a particular offset into the PT stream,
use the following function:

    pt_pkt_sync_set()


There are no checks to ensure that the specified offset is at the beginning of a
packet.  The example below shows synchronization to the first synchronization
point:

~~~{.c}
    struct pt_packet_decoder *decoder;
    int errcode;

    errcode = pt_pkt_sync_forward(decoder);
    if (errcode < 0)
        <handle error>(errcode);
~~~

The decoder will remember the last synchronization packet it decoded.
Subsequent calls to `pt_pkt_sync_forward` and `pt_pkt_sync_backward` will use
this as their starting point.

You can get the current decoder position as offset into the PT buffer via:

    pt_pkt_get_offset()


You can get the position of the last synchronization point as offset into the PT
buffer via:

    pt_pkt_get_sync_offset()


Once the decoder is synchronized, you can iterate over packets by repeated calls
to `pt_pkt_next()` as shown in the following example:

~~~{.c}
    struct pt_packet_decoder *decoder;
    int errcode;

    for (;;) {
        struct pt_packet packet;

        errcode = pt_pkt_next(decoder, &packet);
        if (errcode < 0)
            break;

        <process packet>(&packet);
    }
~~~


## The Event Layer

The event layer deals with packet combinations that encode higher-level events.
It is used for reconstructing execution flow for users who need finer-grain
control not available via the instruction flow layer or for users who want to
integrate execution flow reconstruction with other functionality more tightly
than it would be possible otherwise.

This section describes how to use the query decoder for reconstructing execution
flow.  See the instruction flow decoder as an example.  Start by configuring and
allocating a `pt_query_decoder` as shown below:

~~~{.c}
    struct pt_query_decoder *decoder;
    struct pt_config config;
    int errcode;

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = <pt buffer begin>;
    config.end = <pt buffer end>;
    config.cpu = <cpu identifier>;
    config.decode.callback = <decode function>;
    config.decode.context = <decode context>;

    decoder = pt_qry_alloc_decoder(&config);
    if (!decoder)
        <handle error>(errcode);
~~~

An optional packet decode callback function may be specified in addition to the
mandatory config fields.  If specified, the callback function will be called for
packets the decoder does not know about.  The query decoder will ignore the
unknown packet except for its size in order to skip it.  If there is no decode
callback specified, the decoder will abort with `-pte_bad_opc`.  In addition to
the callback function pointer, an optional pointer to user-defined context
information can be specified.  This context will be passed to the decode
callback function.

Before the decoder can be used, it needs to be synchronized onto the PT stream.
To iterate over synchronization points in the PT stream in forward or backward
direction, the query decoders offer the following two synchronization functions
respectively:


    pt_qry_sync_forward()
    pt_qry_sync_backward()


After successfully synchronizing, the query decoder will start reading the PSB+
header to initialize its internal state.  If tracing is enabled at this
synchronization point, the IP of the instruction, at which decoding should be
started, is returned.  If tracing is disabled at this synchronization point, it
will be indicated in the returned status bits (see below).  In this example,
synchronization to the first synchronization point is shown:

~~~{.c}
    struct pt_query_decoder *decoder;
    uint64_t ip;
    int status;

    status = pt_qry_sync_forward(decoder, &ip);
    if (status < 0)
        <handle error>(status);
~~~

In addition to a query decoder, you will need an instruction decoder for
decoding and classifying instructions.


#### In A Nutshell

After synchronizing, you begin decoding instructions starting at the returned
IP.  As long as you can determine the next instruction in execution order, you
continue on your own.  Only when the next instruction cannot be determined by
examining the current instruction, you would ask the query decoder for guidance:

  * If the current instruction is a conditional branch, the
    `pt_qry_cond_branch()` function will tell whether it was taken.

  * If the current instruction is an indirect branch, the
    `pt_qry_indirect_branch()` function will provide the IP of its destination.


~~~{.c}
    struct pt_query_decoder *decoder;
    uint64_t ip;

    for (;;) {
        struct <instruction> insn;

        insn = <decode instruction>(ip);

        ip += <instruction size>(insn);

        if (<is cond branch>(insn)) {
            int status, taken;

            status = pt_qry_cond_branch(decoder, &taken);
            if (status < 0)
                <handle error>(status);

            if (taken)
                ip += <branch displacement>(insn);
        } else if (<is indirect branch>(insn)) {
            int status;

            status = pt_qry_indirect_branch(decoder, &ip);
            if (status < 0)
                <handle error>(status);
        }
    }
~~~


Certain aspects such as, for example, asynchronous events or synchronizing at a
location where tracing is disabled, have been ignored so far.  Let us consider
them now.


#### Queries

The query decoder provides four query functions:

  * `pt_qry_cond_branch()`      Query whether the next conditional branch was
                                taken.

  * `pt_qry_indirect_branch()`  Query for the destination IP of the next
                                indirect branch.

  * `pt_qry_event()`            Query for the next event.

  * `pt_qry_time()`             Query for the current time.


Each function returns either a positive vector of status bits or a negative
error code.  For details on status bits and error conditions, please refer to
the `pt_status_flag` and `pt_error_code` enumerations in the intel-pt.h header.

The `pts_ip_suppressed` status bit is used to indicate that no IP is available
at functions that are supposed to return an IP.  Examples are the indirect
branch query function and both synchronization functions.

The `pts_event_pending` status bit is used to indicate that there is an event
pending.  You should query for this event before continuing execution flow
reconstruction.


#### Events

Events are signaled ahead of time.  When you query for pending events as soon as
they are indicated, you will be aware of asynchronous events before you reach
the instruction associated with the event.

For example, if tracing is disabled at the synchronization point, the IP will be
suppressed.  In this case, it is very likely that a tracing enabled event is
signaled.  You will also get events for initializing the decoder state after
synchronizing onto the PT stream.  For example, paging or execution mode events.

See the `enum pt_event_type` and `struct pt_event` in the intel-pt.h header for
details on possible events.  This document does not give an example of event
processing.  Refer to the implementation of the instruction flow decoder in
pt_insn.c for details.


#### Timing

To be able to signal events, the decoder reads ahead until it arrives at a query
relevant packet.  Errors encountered during that time will be postponed until
the respective query call.  This reading ahead affects timing.  The decoder will
always be a few packets ahead.  When querying for the current time, the query
will return the time at the decoder's current packet.  This corresponds to the
time at our next query.


#### Return Compression

If PT has been configured to compress returns, a successfully compressed return
is represented as a conditional branch instead of an indirect branch.  For a RET
instruction, you first query for a conditional branch.  If the query succeeds,
it should indicate that the branch was taken.  In that case, the return has been
compressed.  A not taken branch indicates an error.  If the query fails, the
return has not been compressed and you query for an indirect branch.

There is no guarantee that returns will be compressed.  Even though return
compression has been enabled, returns may still be represented as indirect
branches.

To reconstruct the execution flow for compressed returns, you would maintain a
stack of return addresses.  For each call instruction, push the IP of the
instruction following the call onto the stack.  For compressed returns, pop the
topmost IP from the stack.  See pt_retstack.h and pt_retstack.c for a sample
implementation.


## The Instruction Flow Layer

The instruction flow layer provides a simple API for iterating over instructions
in execution order.  Start by configuring and allocating a `pt_insn_decoder` as
shown below:

~~~{.c}
    struct pt_insn_decoder *decoder;
    struct pt_config config;
    int errcode;

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = <pt buffer begin>;
    config.end = <pt buffer end>;
    config.cpu = <cpu identifier>;
    config.decode.callback = <decode function>;
    config.decode.context = <decode context>;

    decoder = pt_insn_alloc_decoder(&config);
    if (!decoder)
        <handle error>(errcode);
~~~

An optional packet decode callback function may be specified in addition to the
mandatory config fields.  If specified, the callback function will be called for
packets the decoder does not know about.  The decoder will ignore the unknown
packet except for its size in order to skip it.  If there is no decode callback
specified, the decoder will abort with `-pte_bad_opc`.  In addition to the
callback function pointer, an optional pointer to user-defined context
information can be specified.  This context will be passed to the decode
callback function.


#### The Process Image

In addition to the PT configuration, the instruction flow decoder needs to know
the process image, for which PT has been recorded.  This can be specified by
repeated calls to `pt_insn_add_file()`, one for each section of contiguous
memory.

If decoding failed due to an IP lying outside the specified process image,
`pt_insn_next()` will return `-pte_nomap`.

In some cases, the process image may change during the execution.  You can use
the `pt_insn_remove_by_filename()` function to remove previously added sections
by their file name.  You can also add new sections by calling
`pt_insn_add_file()` at any time.

If you prefer to manage the image on your own, you can register a callback
function for reading memory using `pt_insn_add_callback()`.  The `context`
parameter you pass together with the callback function pointer will be passed
to your callback function every time it is called.

Callback and files may be combined.  The callback function is used whenever
the memory cannot be found in the image specified by `pt_insn_add_file()`
calls.


#### Synchronizing

Before the decoder can be used, it needs to be synchronized onto the PT stream.
To iterate over synchronization points in the PT stream in forward or backward
directions, the instruction flow decoders offer the following two
synchronization functions respectively:

    pt_insn_sync_forward()
    pt_insn_sync_backward()


The example below shows synchronization to the first synchronization point:

~~~{.c}
    struct pt_insn_decoder *decoder;
    int errcode;

    errcode = pt_insn_sync_forward(decoder);
    if (errcode < 0)
        <handle error>(errcode);
~~~

The decoder will remember the last synchronization packet it decoded.
Subsequent calls to `pt_insn_sync_forward` and `pt_insn_sync_backward` will use
this as their starting point.

You can get the current decoder position as offset into the PT buffer via:

    pt_insn_get_offset()


You can get the position of the last synchronization point as offset into the PT
buffer via:

    pt_insn_get_sync_offset()


#### Iterating

Once the decoder is synchronized, you can iterate over instructions in execution
flow order by repeated calls to `pt_insn_next()` as shown in the following
example:

~~~{.c}
    struct pt_insn_decoder *decoder;
    int errcode;

    for (;;) {
        struct pt_insn insn;

        errcode = pt_insn_next(decoder, &insn);
        if (errcode < 0)
            break;

        <process instruction>(&insn);
    }
~~~

For each instruction, you get its IP, its size in bytes, the raw memory, the
current execution mode, and the speculation state, that is whether the
instruction has been executed speculatively.  In addition, you get a coarse
classification that can be used for further processing without the need for a
full instruction decode.

You also get some information about events that occured either before or after
executing the instruction like enable or disable tracing.  For detailed
information about instructions, see `enum pt_insn_class` and `struct pt_insn` in
the intel-pt.h header file.


## Threading

The decoder library API is not thread-safe.  Different threads may allocate and
use different decoder objects at the same time.
