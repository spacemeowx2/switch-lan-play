cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

if (${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
    set(CMAKE_C_FLAGS_DEBUG
        "-g3 -ggdb -g"
    )
endif()

include(TestBigEndian)
test_big_endian(BIG_ENDIAN)
if (BIG_ENDIAN)
    add_definitions(-DLANPLAY_BIG_ENDIAN)
else ()
    add_definitions(-DLANPLAY_LITTLE_ENDIAN)
endif ()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-DLANPLAY_LINUX)

    # How to detect android or termux in cmake? https://github.com/termux/termux-packages/issues/151
    EXECUTE_PROCESS(COMMAND uname -o COMMAND tr -d '\n' OUTPUT_VARIABLE OPERATING_SYSTEM)
    if(${OPERATING_SYSTEM} MATCHES "Android")
        set(OS_ANDROID 1)
    endif(${OPERATING_SYSTEM} MATCHES "Android")
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    add_definitions(-DLANPLAY_FREEBSD)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_definitions(-DLANPLAY_DARWIN)
endif()

# add external libraries
include(external/external.cmake)

add_subdirectory(base)
add_subdirectory(lwip)
add_subdirectory(uv_lwip)
add_subdirectory(src)
