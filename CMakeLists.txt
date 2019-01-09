cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# add external libraries
include(external/external.cmake)

set(CMAKE_C_FLAGS_DEBUG
    "-g3 -ggdb -g"
)

include(TestBigEndian)
test_big_endian(BIG_ENDIAN)
if (BIG_ENDIAN)
    add_definitions(-DLANPLAY_BIG_ENDIAN)
else ()
    add_definitions(-DLANPLAY_LITTLE_ENDIAN)
endif ()
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-DLANPLAY_LINUX)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    add_definitions(-DLANPLAY_FREEBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_definitions(-DLANPLAY_DARWIN)
endif()

add_subdirectory(base)
add_subdirectory(lwip)
add_subdirectory(uv_lwip)
add_subdirectory(src)
