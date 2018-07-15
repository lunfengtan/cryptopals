#######################################################################
# Top level build file for cryptopals
#######################################################################

cmake_minimum_required (VERSION 3.0)
project (cryptopals)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

#######################################################################
# Cryptopals library
#######################################################################

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARIES})

add_subdirectory (lib)
include_directories (lib)

#######################################################################
# Problem sets
#######################################################################
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fsanitize=address")

add_subdirectory (modules/set1)
add_subdirectory (modules/set2)
