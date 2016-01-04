#! /bin/bash
#
# Copyright (c) 2015-2016, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#  * Neither the name of Intel Corporation nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

set -e

prog=`basename $0`

usage() {
    cat <<EOF
usage: $prog [<options>] <perf.data-file>

Scan the perf data file for MMAP records and print ptxed options for
constructing a corresponding image.

<perf.data-file> defaults to perf.data.
EOF
}


if [[ $# == 0 ]]; then
    file="perf.data"
elif [[ $# == 1 ]]; then
    file="$1"
    shift
else
    usage
    exit 1
fi


perf script --no-itrace -i "$file" -D | gawk -F' ' -- '
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
'
