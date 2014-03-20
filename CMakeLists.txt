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

cmake_minimum_required(VERSION 2.6)

project(PT)

# versioning
#
# the major and the minor number define the supported PT set.
#
# a build number and a version extension can be optionally specified.
#
set(PT_VERSION_MAJOR 1)
set(PT_VERSION_MINOR 2)
set(PT_VERSION_BUILD "0" CACHE STRING "")
set(PT_VERSION_EXT "" CACHE STRING "")

add_definitions(
  -DPT_VERSION_MAJOR=${PT_VERSION_MAJOR}
  -DPT_VERSION_MINOR=${PT_VERSION_MINOR}
  -DPT_VERSION_BUILD=${PT_VERSION_BUILD}
  -DPT_VERSION_EXT=\"${PT_VERSION_EXT}\"
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_COLOR_MAKEFILE   OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(XED_INCLUDE "" CACHE PATH "")
set(XED_LIBDIR  "" CACHE PATH "")

set(FEATURE_MMAP "" CACHE BOOL OFF)
if (FEATURE_MMAP)
  add_definitions(-DFEATURE_MMAP)
endif (FEATURE_MMAP)

set(FEATURE_ELF "" CACHE BOOL OFF)
if (FEATURE_ELF)
  add_definitions(-DFEATURE_ELF)
endif (FEATURE_ELF)

include_directories(
  include
  libipt/include
  ptunit/include
)

if (CMAKE_HOST_WIN32)
  include_directories(
    include/windows
  )

  add_definitions(
    # cl spells inline __inline in C
    #
    /Dinline=__inline

    # cl spells strtoll _strtoi64
    #
    /Dstrtoll=_strtoi64

    # cl spells strtoull _strtoui64
    #
    /Dstrtoull=_strtoui64

    # avoid annoying warnings about unsecure standard functions
    #
    /D_CRT_SECURE_NO_WARNINGS
  )

  # enable parallel build
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

  # compiler warnings
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")

  # allow functions to ignore parameters
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4100")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4100")

  # prevent complaints on:
  # - do {} while(0) constructs
  # - unreferenced function parameters
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4127")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4127")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd869")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd869")

  # warnings are errors
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX")

endif (CMAKE_HOST_WIN32)

if (CMAKE_HOST_UNIX)

  if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_definitions(
      # make asm directive work in c99 mode.
      #
      # from the clang user manual:
      # "The parser recognizes "asm" and "typeof" as keywords in gnu* modes;
      # the variants "__asm__" and "__typeof__" are recognized in all
      # modes."
      -Dasm=__asm__
    )
  endif (CMAKE_C_COMPILER_ID MATCHES "Clang")

  set(GCOV "" CACHE BOOL OFF)

  if (GCOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftest-coverage")

    link_libraries(gcov)
  endif (GCOV)

  set(CHECK "" CACHE BOOL ON)

  # set the language
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

  # windows-like dll export model
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

  # compiler warnings
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")

  # allow functions to ignore parameters
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")

  # warnings are errors
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

  # track dependencies
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -MMD")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -MMD")

endif (CMAKE_HOST_UNIX)

find_package(Doxygen)

if (DOXYGEN_FOUND)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doc/doxygen/Doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

  add_custom_target(doc
    ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
endif(DOXYGEN_FOUND)

add_subdirectory(libipt)
add_subdirectory(ptdump)
add_subdirectory(ptxed)
add_subdirectory(pttc)
add_subdirectory(ptunit)
