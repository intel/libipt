# Copyright (c) 2013, Intel Corporation
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

if (CMAKE_HOST_UNIX)
  add_definitions(
    # build position independent
    #
    -fPIC
  )
endif (CMAKE_HOST_UNIX)

if (CMAKE_HOST_WIN32)
  add_definitions(
    # export libipt symbols
    #
    /Dpt_export=__declspec\(dllexport\)
  )
endif (CMAKE_HOST_WIN32)

include_directories(
  internal/include
)

set(LIBIPT_FILES
  src/pt_config.c
  src/pt_encode.c
  src/pt_error.c
  src/pt_packet_decode.c
  src/pt_query.c
  src/pt_state.c
  src/pt_sync.c
  src/pt_version.c
  src/pt_packet.c
  src/pt_last_ip.c
  src/pt_tnt_cache.c
)

add_library(ipt SHARED
  ${LIBIPT_FILES}
)

if (CHECK)
  add_executable(check-libipt
    ${LIBIPT_FILES}

    test/src/check.c
    test/src/check_pt_packet_decode.c
    test/src/check_pt_state.c
    test/src/check_pt_sync.c
    test/src/check_pt_use.c
    test/src/check_pt_packet.c
    test/src/pt_decoder_fixture.c
  )

  include_directories(test/include)
  target_link_libraries(check-libipt check)
endif (CHECK)

add_executable(ptunit-last_ip
  test/src/ptunit-last_ip.c
  src/pt_last_ip.c
)

add_executable(ptunit-tnt_cache
  test/src/ptunit-tnt_cache.c
  src/pt_tnt_cache.c
)

add_executable(ptunit-query
  test/src/ptunit-query.c
  src/pt_query.c
  src/pt_encode.c
  src/pt_last_ip.c
  src/pt_state.c
  src/pt_packet_decode.c
  src/pt_sync.c
  src/pt_tnt_cache.c
  src/pt_config.c
)

target_link_libraries(ptunit-last_ip ptunit)
target_link_libraries(ptunit-tnt_cache ptunit)
target_link_libraries(ptunit-query ptunit)
