# Copyright (c) 2013-2015, Intel Corporation
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

set(LIBIPT_SECTION_FILES
  src/pt_section.c
  src/pt_section_file.c
)

set(LIBIPT_FILES
  src/pt_error.c
  src/pt_packet_decoder.c
  src/pt_query_decoder.c
  src/pt_encoder.c
  src/pt_sync.c
  src/pt_version.c
  src/pt_last_ip.c
  src/pt_tnt_cache.c
  src/pt_ild.c
  src/pt_image.c
  src/pt_retstack.c
  src/pt_insn_decoder.c
  src/pt_time.c
  src/pt_mapped_section.c
  src/pt_asid.c
  src/pt_event_queue.c
  src/pt_packet.c
  src/pt_decoder_function.c
  src/pt_config.c
)

if (CMAKE_HOST_UNIX)
  include_directories(
    internal/include/posix
  )

  set(LIBIPT_FILES ${LIBIPT_FILES} src/posix/init.c)
  set(LIBIPT_SECTION_FILES ${LIBIPT_SECTION_FILES} src/posix/pt_section_posix.c)
endif (CMAKE_HOST_UNIX)

if (CMAKE_HOST_WIN32)
  add_definitions(
    # export libipt symbols
    #
    /Dpt_export=__declspec\(dllexport\)
  )

  include_directories(
    internal/include/windows
  )

  set(LIBIPT_FILES ${LIBIPT_FILES} src/windows/init.c)
  set(LIBIPT_SECTION_FILES ${LIBIPT_SECTION_FILES} src/windows/pt_section_windows.c)
endif (CMAKE_HOST_WIN32)

set(LIBIPT_FILES ${LIBIPT_FILES} ${LIBIPT_SECTION_FILES})

add_library(libipt SHARED
  ${LIBIPT_FILES}
)

set_target_properties(libipt PROPERTIES
  PREFIX ""
  PUBLIC_HEADER include/intel-pt.h
  VERSION   ${PT_VERSION}
  SOVERSION ${PT_VERSION_MAJOR}
)

install(TARGETS libipt
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)


if (PTUNIT)
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
    src/pt_encoder.c
    src/pt_last_ip.c
    src/pt_packet_decoder.c
    src/pt_sync.c
    src/pt_tnt_cache.c
    src/pt_time.c
    src/pt_event_queue.c
    src/pt_query_decoder.c
    src/pt_packet.c
    src/pt_decoder_function.c
    src/pt_packet_decoder.c
    src/pt_config.c
    ${LIBIPT_SECTION_FILES}
    src/pt_time.c
  )

  add_executable(ptunit-cpp
    test/src/ptunit-cpp.cpp
  )

  add_executable(ptunit-retstack
    test/src/ptunit-retstack.c
    src/pt_retstack.c
  )

  add_executable(ptunit-section
    test/src/ptunit-section.c
    ${LIBIPT_SECTION_FILES}
  )

  add_executable(ptunit-image
    test/src/ptunit-image.c
    src/pt_mapped_section.c
    src/pt_asid.c
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

  add_executable(ptunit-time
    test/src/ptunit-time.c
    src/pt_time.c
  )

  add_executable(ptunit-mapped_section
    test/src/ptunit-mapped_section.c
    src/pt_mapped_section.c
    src/pt_asid.c
  )

  add_executable(ptunit-asid
    test/src/ptunit-asid.c
    src/pt_asid.c
  )

  add_executable(ptunit-event_queue
    test/src/ptunit-event_queue.c
    src/pt_event_queue.c
  )

  add_executable(ptunit-packet
    test/src/ptunit-packet.c
    src/pt_encoder.c
    src/pt_packet_decoder.c
    src/pt_sync.c
    src/pt_packet.c
    src/pt_decoder_function.c
    src/pt_config.c
  )

  add_executable(ptunit-sync
    test/src/ptunit-sync.c
    src/pt_sync.c
    src/pt_packet.c
  )

  add_executable(ptunit-fetch
    test/src/ptunit-fetch.c
    src/pt_decoder_function.c
    src/pt_encoder.c
    src/pt_config.c
  )

  add_executable(ptunit-config
    test/src/ptunit-config.c
    src/pt_config.c
  )

  target_link_libraries(ptunit-last_ip ptunit)
  target_link_libraries(ptunit-tnt_cache ptunit)
  target_link_libraries(ptunit-query ptunit)
  target_link_libraries(ptunit-cpp ptunit libipt)
  target_link_libraries(ptunit-retstack ptunit)
  target_link_libraries(ptunit-section ptunit)
  target_link_libraries(ptunit-image ptunit)
  target_link_libraries(ptunit-ild ptunit)
  target_link_libraries(ptunit-cpu ptunit)
  target_link_libraries(ptunit-time ptunit)
  target_link_libraries(ptunit-mapped_section ptunit)
  target_link_libraries(ptunit-asid ptunit)
  target_link_libraries(ptunit-event_queue ptunit)
  target_link_libraries(ptunit-packet ptunit)
  target_link_libraries(ptunit-sync ptunit)
  target_link_libraries(ptunit-fetch ptunit)
  target_link_libraries(ptunit-config ptunit)

endif (PTUNIT)
