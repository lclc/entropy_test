# The MIT License (MIT)
# Copyright (c) 2015 Lucas Betschart
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
# OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.2)

project(entropy_test)


#-----------------------------------------------------------------------------
# Compiler flags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")


#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Get submodules

execute_process(COMMAND git "submodule" "update" "--init" "--recursive" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


# Testing (lclc remove later)
add_definitions(-DTESTING)


#-----------------------------------------------------------------------------
# Force out-of-source build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif()


#-----------------------------------------------------------------------------
# Default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()


#-----------------------------------------------------------------------------
# Get HIDAPI USB Library

find_library(HIDAPI_LIBRARY
	NAMES hidapi hidapi-libusb)

find_path(HIDAPI_INCLUDE_DIR
	NAMES hidapi.h
	PATH_SUFFIXES
	hidapi)

if(!HIDAPI_FOUND)
    message(FATAL_ERROR "hidapi not found.")
endif()


#-----------------------------------------------------------------------------
# Build Bibox library

add_subdirectory(bitbox_mcu)


include_directories(SYSTEM
                    ${HIDAPI_INCLUDE_DIR}
                    bitbox_mcu/src
)


#-----------------------------------------------------------------------------
# Build

add_executable(entropy_test main.c)

target_link_libraries(entropy_test ${HIDAPI_LIBRARY} bitbox)
