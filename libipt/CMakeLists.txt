# Copyright (c) 2013-2014, Intel Corporation
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

include_directories(
  internal/include
)

set(LIBIPT_CONFIG_FILES
  src/pt_config.c
)

set(LIBIPT_FILES
  src/pt_error.c
  src/pt_packet_decode.c
  src/pt_packet_decoder.c
  src/pt_query_decoder.c
  src/pt_query.c
  src/pt_encoder.c
  src/pt_decoder.c
  src/pt_sync.c
  src/pt_version.c
  src/pt_last_ip.c
  src/pt_tnt_cache.c
  src/pt_ild.c
  src/pt_image.c
  src/pt_retstack.c
  src/pt_insn_decoder.c
  src/pt_insn.c
)

if (FEATURE_MMAP)
  set(LIBIPT_FILES ${LIBIPT_FILES} src/posix/pt_section_mmap.c)
else (FEATURE_MMAP)
  set(LIBIPT_FILES ${LIBIPT_FILES} src/pt_section_file.c)
endif (FEATURE_MMAP)

if (CMAKE_HOST_UNIX)
  # build position independent
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

  set(LIBIPT_FILES ${LIBIPT_FILES} src/posix/init.c)
  set(LIBIPT_CONFIG_FILES ${LIBIPT_CONFIG_FILES} src/posix/pt_cpuid.c)
endif (CMAKE_HOST_UNIX)

if (CMAKE_HOST_WIN32)
  add_definitions(
    # export libipt symbols
    #
    /Dpt_export=__declspec\(dllexport\)
  )
  set(LIBIPT_FILES ${LIBIPT_FILES} src/windows/init.c)
  set(LIBIPT_CONFIG_FILES ${LIBIPT_CONFIG_FILES} src/windows/pt_cpuid.c)
endif (CMAKE_HOST_WIN32)

set(LIBIPT_FILES ${LIBIPT_FILES} ${LIBIPT_CONFIG_FILES})

add_library(libipt SHARED
  ${LIBIPT_FILES}
)

set_target_properties(libipt PROPERTIES PREFIX "")

if (CHECK)
  add_executable(check-libipt
    ${LIBIPT_FILES}

    test/src/check.c
    test/src/check_pt_packet_decode.c
    test/src/check_pt_decoder.c
    test/src/check_pt_sync.c
    test/src/check_pt_use.c
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
  src/pt_encoder.c
  src/pt_last_ip.c
  src/pt_decoder.c
  src/pt_packet_decode.c
  src/pt_sync.c
  src/pt_tnt_cache.c
  ${LIBIPT_CONFIG_FILES}
)

add_executable(ptunit-cpp
  test/src/ptunit-cpp.cpp
)

add_executable(ptunit-retstack
  test/src/ptunit-retstack.c
  src/pt_retstack.c
)

add_executable(ptunit-section_file
  test/src/ptunit-section.c
  src/pt_section_file.c
)

add_executable(ptunit-image
  test/src/ptunit-image.c
  src/pt_image.c
)

add_executable(ptunit-ild
  test/src/ptunit-ild.c
  src/pt_ild.c
)

add_executable(ptunit-cpu
  test/src/ptunit-cpu.c
  src/pt_cpu.c
)

target_link_libraries(ptunit-last_ip ptunit)
target_link_libraries(ptunit-tnt_cache ptunit)
target_link_libraries(ptunit-query ptunit)
target_link_libraries(ptunit-cpp ptunit libipt)
target_link_libraries(ptunit-retstack ptunit)
target_link_libraries(ptunit-section_file ptunit)
target_link_libraries(ptunit-image ptunit)
target_link_libraries(ptunit-ild ptunit)
target_link_libraries(ptunit-cpu ptunit)

if (FEATURE_MMAP)
  add_executable(ptunit-section_mmap
    test/src/ptunit-section.c
    src/posix/pt_section_mmap.c
  )
  target_link_libraries(ptunit-section_mmap ptunit)
endif (FEATURE_MMAP)
