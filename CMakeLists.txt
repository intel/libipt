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

cmake_minimum_required(VERSION 2.8.6)

project(PT)

# versioning
#
# the major and the minor number define the supported Intel PT set.
#
# a build number and a version extension can be optionally specified.
#
set(PT_VERSION_MAJOR 1)
set(PT_VERSION_MINOR 4)
set(PT_VERSION_BUILD "0" CACHE STRING "")
set(PT_VERSION_EXT "" CACHE STRING "")

set(PT_VERSION "${PT_VERSION_MAJOR}.${PT_VERSION_MINOR}.${PT_VERSION_BUILD}")

add_definitions(
  -DPT_VERSION_MAJOR=${PT_VERSION_MAJOR}
  -DPT_VERSION_MINOR=${PT_VERSION_MINOR}
  -DPT_VERSION_BUILD=${PT_VERSION_BUILD}
  -DPT_VERSION_EXT=\"${PT_VERSION_EXT}\"
)

include(GNUInstallDirs)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_COLOR_MAKEFILE   OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_MACOSX_RPATH ON)

option(FEATURE_THREADS "A small amount of multi-threading support." OFF)
if (FEATURE_THREADS)
  add_definitions(-DFEATURE_THREADS)
endif (FEATURE_THREADS)

option(DEVBUILD "Enable compiler warnings and turn them into errors." OFF)

option(PTDUMP "Enable ptdump, a packet dumper")
option(PTXED  "Enable ptxed, an instruction flow dumper")
option(PTTC   "Enable pttc, a test compiler")
option(PTUNIT "Enable ptunit, a unit test system and libipt unit tests")

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

    # cl forgot to declare snprintf
    #
    /Dsnprintf=_snprintf_c

    # avoid annoying warnings about unsecure standard functions
    #
    /D_CRT_SECURE_NO_WARNINGS
  )

  # enable parallel build
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

  if (DEVBUILD)
    # compiler warnings
    #
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")

    # warnings are errors
    #
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX")
  endif (DEVBUILD)

  if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
    # prevent complaints on:
    # - do {} while(0) constructs
    #
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4127")

  endif (CMAKE_C_COMPILER_ID MATCHES "MSVC")

  if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    # prevent complaints on:
    # - do {} while(0) constructs
    #
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4127")

  endif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")

endif (CMAKE_HOST_WIN32)

if (CMAKE_HOST_UNIX)
  include_directories(
    include/posix
  )

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

  option(GCOV "Compile for GNU code coverage analysis." OFF)

  if (GCOV)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftest-coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftest-coverage")

    link_libraries(gcov)
  endif (GCOV)

  if (FEATURE_THREADS)
    link_libraries(pthread)
  endif (FEATURE_THREADS)

  # set the language
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

  # windows-like dll export model
  #
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

  if (DEVBUILD)
    # compiler warnings
    #
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")

    # warnings are errors
    #
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
  endif (DEVBUILD)

endif (CMAKE_HOST_UNIX)

add_subdirectory(libipt)

if (PTDUMP)
  add_subdirectory(ptdump)
endif (PTDUMP)
if (PTXED)
  add_subdirectory(ptxed)
endif (PTXED)
if (PTTC)
  add_subdirectory(pttc)
endif (PTTC)
if (PTUNIT)
  add_subdirectory(ptunit)
endif (PTUNIT)
