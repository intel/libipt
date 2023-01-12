Capturing Intel(R) Processor Trace (Intel PT) {#capture}
=============================================

<!---
 ! Copyright (c) 2015-2023, Intel Corporation
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

This chapter describes how to capture Intel PT for processing with libipt.  For
illustration, we use the sample tools ptdump and ptxed.


## Capturing Intel PT on Linux

Starting with version 4.1, the Linux kernel supports Intel PT via the perf_event
kernel interface.  Starting with version 4.3, the perf user-space tool will
support Intel PT as well.


### Capturing Intel PT via Linux perf_event

We start with setting up a perf_event_attr object for capturing Intel PT.  The
structure is declared in `/usr/include/linux/perf_event.h`.

The Intel PT PMU type is dynamic.  Its value can be read from
`/sys/bus/event_source/devices/intel_pt/type`.

~~~{.c}
    struct perf_event_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = <read type>();

    attr.exclude_kernel = 1;
    ...
~~~


Once all desired fields have been set, we can open a perf_event counter for
Intel PT.  See `man 2 perf_event_open` for details.  In our example, we
configure it for tracing a single thread.

The system call returns a file descriptor on success, `-1` otherwise.

~~~{.c}
    int fd;

    fd = syscall(SYS_perf_event_open, &attr, <pid>, -1, -1, 0);
~~~


The Intel PT trace is captured in the AUX area, which has been introduced with
kernel 4.1.  The DATA area contains sideband information such as image changes
that are necessary for decoding the trace.

In theory, both areas can be configured as circular buffers or as linear buffers
by mapping them read-only or read-write, respectively.  When configured as
circular buffer, new data will overwrite older data.  When configured as linear
buffer, the user is expected to continuously read out the data and update the
buffer's tail pointer.  New data that do not fit into the buffer will be
dropped.

When using the AUX area, its size and offset have to be filled into the
`perf_event_mmap_page`, which is mapped together with the DATA area.  This
requires the DATA area to be mapped read-write and hence configured as linear
buffer.  In our example, we configure the AUX area as circular buffer.

Note that the size of both the AUX and the DATA area has to be a power of two
pages.  The DATA area needs one additional page to contain the
`perf_event_mmap_page`.

~~~{.c}
    struct perf_event_mmap_page *header;
    void *base, *data, *aux;

    base = mmap(NULL, (1+2**n) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED)
        return <handle data mmap error>();

    header = base;
    data = base + header->data_offset;

    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size   = (2**m) * PAGE_SIZE;

    aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, fd,
               header->aux_offset);
    if (aux == MAP_FAILED)
        return <handle aux mmap error>();
~~~


### Capturing Intel PT via the perf user-space tool

Starting with kernel 4.3, the perf user-space tool can be used to capture Intel
PT with the `intel_pt` event.  See tools/perf/Documentation in the Linux kernel
tree for further information.  In this text, we describe how to use the captured
trace with the ptdump and ptxed sample tools.

We start with capturing some Intel PT trace using the intel_pt event.

~~~{.sh}
    $ perf record -e intel_pt//u --per-thread -- grep -r foo /usr/include
    [ perf record: Woken up 26 times to write data ]
    [ perf record: Captured and wrote 51.969 MB perf.data ]
~~~


This generates a `perf.data` file that contains the Intel PT trace, the sideband
information, and some metadata.  To process the trace with libipt, we need to
extract the Intel PT trace into one file per thread or cpu.

Looking at the raw trace dump of `perf script -D`, we notice
`PERF_RECORD_AUXTRACE` records.  The raw Intel PT trace is contained directly
after such records.  We can extract it with the `dd` command.  The arguments to
`dd` can be computed from the record's fields.  This can be done automatically,
for example with an AWK script.

~~~{.awk}
  /PERF_RECORD_AUXTRACE / {
    offset = strtonum($1)
    hsize  = strtonum(substr($2, 2))
    size   = strtonum($5)
    idx    = strtonum($11)

    ofile = sprintf("perf.data-aux-idx%d.bin", idx)
    begin = offset + hsize

    cmd = sprintf("dd if=perf.data of=%s conv=notrunc oflag=append ibs=1 \
                  skip=%d count=%d status=none", ofile, begin, size)

    system(cmd)
  }
~~~

The libipt tree contains such a script in `script/perf-read-aux.bash`.

In addition to the Intel PT trace, we need the traced memory image.  When
tracing a single process where the memory image does not change during tracing,
we can construct the memory image by examining `PERF_RECORD_MMAP` and
`PERF_RECORD_MMAP2` records.  This can again be done automatically, for example
with an AWK script.

~~~{.awk}
  function handle_mmap(file, vaddr) {
    if (match(file, /\[.*\]/) != 0) {
      # ignore 'virtual' file names like [kallsyms]
    }
    else if (match(file, /\.ko$/) != 0) {
      # ignore kernel objects
      #
      # use /proc/kcore
    }
    else {
      printf(" --elf %s:0x%x", file, vaddr)
    }
  }

  /PERF_RECORD_MMAP / {
    vaddr = strtonum(substr($5, 2))
    file = $9

    handle_mmap(file, vaddr)
  }

  /PERF_RECORD_MMAP2 / {
    vaddr = strtonum(substr($5, 2))
    file = $12

    handle_mmap(file, vaddr)
  }
~~~

The above script generates options for the `ptxed` sample tool.  The libipt tree
contains such a script in `script/perf-read-image.bash`.

Let's put it all together.

~~~{.sh}
    $ perf record -e intel_pt//u --per-thread -- grep -r foo /usr/include
    [ perf record: Woken up 26 times to write data ]
    [ perf record: Captured and wrote 51.969 MB perf.data ]
    $ script/perf-read-aux.bash
    $ script/perf-read-image.bash | xargs ptxed --cpu 6/61 --pt perf.data-aux-idx0.bin
~~~


### Sideband support

The above example does not consider sideband information.  It therefore only
works for not-too-complicated single-threaded applications.  For tracing
multi-threaded applications or for system-wide tracing (including ring-3),
sideband information is required for decoding the trace.

Sideband information can be defined as any information necessary for decoding
Intel PT that is not contained in the trace stream itself.  We already supply:

  * the binary files whose execution was traced and the virtual address at which
    each file was loaded
  * the family/model/stepping of the processor on which the trace was recorded
  * some information regarding timing


What's missing is information about changes to the traced memory image while the
trace is being recorded:

  * memory map/unamp information
  * context switch information


On Linux, this information can be found in the form of PERF_EVENT records in the
DATA buffer or in the perf.data file respectively.

Collection and interpretation of this information is currently left completely
to the user.


### Capturing Intel PT via Simple-PT

The Simple-PT project on github supports capturing Intel PT on Linux with an
alternative kernel driver.  The spt decoder supports sideband information.

See the project's page at https://github.com/andikleen/simple-pt for more
information including examples.
