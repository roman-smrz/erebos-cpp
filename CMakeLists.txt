cmake_minimum_required(VERSION 3.10)
project(Erebos)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(B2_LIBRARY b2 REQUIRED)
find_library(UUID_LIBRARY uuid REQUIRED)

add_subdirectory(src)
