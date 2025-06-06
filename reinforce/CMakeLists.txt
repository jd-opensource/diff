cmake_minimum_required(VERSION 3.4)
project(llvm-pass-tutorial)

# we need LLVM_HOME in order not automatically set LLVM_DIR
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
link_directories(${LLVM_LIBRARY_DIRS})
if (${LLVM_VERSION_MAJOR} VERSION_GREATER_EQUAL 10)
    set(CMAKE_CXX_STANDARD 14)
endif ()

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
include_directories($ENV{LLVM_HOME}/include/c++v1)
set(CMAKE_SKIP_RPATH ON)

add_subdirectory(Hikari)  # Hikari
