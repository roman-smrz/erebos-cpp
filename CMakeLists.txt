cmake_minimum_required(VERSION 3.10)
project(Erebos)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	add_compile_options(-Wno-unqualified-std-cast-call)
endif()

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_library(B2_LIBRARY b2 REQUIRED)

add_subdirectory(src)
