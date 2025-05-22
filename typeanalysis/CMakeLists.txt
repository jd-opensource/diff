cmake_minimum_required(VERSION 3.4)
project(preparsers)
include(CMakePrintHelpers)


if(NOT DEFINED ENV{LLVM_HOME})
    message(FATAL_ERROR "$LLVM_HOME is not defined")
else()
    if(EXISTS $ENV{LLVM_HOME}/lib64)
        set(ENV{LLVM_DIR} $ENV{LLVM_HOME}/lib64/cmake/llvm)
    else()
        set(ENV{LLVM_DIR} $ENV{LLVM_HOME}/lib/cmake/llvm)
    endif()
endif()


find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

include_directories(${LLVM_INCLUDE_DIRS})
include_directories($ENV{LLVM_HOME}/include)

link_directories(${LLVM_LIBRARY_DIRS})

set(CMAKE_CXX_STANDARD 14)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-everything -lm -lffi -stdlib=libc++") 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-everything -lm -lffi") 
endif()

add_subdirectory(parsers)
