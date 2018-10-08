cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)
set(LANPLAY_VERSION 0.0.1)

add_compile_options(
    "-Wall"
    "-Wno-unused-function"
    "-DLANPLAY_VERSION=\"${LANPLAY_VERSION}\""
)
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

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    lwip/custom
    lwip/src/include
    src
)
add_subdirectory(lwip)

if (WIN32)
    include(ExternalProject)
    ExternalProject_Add(
        winpcap
        PREFIX ${CMAKE_BINARY_DIR}/winpcap
        URL "https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip"
        URL_MD5 "bae2236af062b0900ad1416b2c4878b9"
        CONFIGURE_COMMAND "" BUILD_COMMAND "" INSTALL_DIR "" INSTALL_COMMAND ""
        # LOG_DOWNLOAD ON
    )
    ExternalProject_Get_Property(winpcap SOURCE_DIR)
    set(PCAP_ROOT_DIR ${SOURCE_DIR})
    set(PCAP_INCLUDE_DIR ${SOURCE_DIR}/Include)
    set(PCAP_LIBRARY ${SOURCE_DIR}/Lib/x64/wpcap.lib)
    message("PCAP_ROOT_DIR = ${PCAP_ROOT_DIR} INCLUDE = ${PCAP_INCLUDE_DIR}")
else()
    include(cmake/FindPCAP.cmake)
endif()

set(SOURCE_FILES
    src/main.c
    src/packet.c
    src/arp.c
    src/helper.c
    src/lan-client.c
    src/gateway.c
    src/proxy.c
    src/ipv4/ipv4.c
    src/ipv4/tcp.c
    src/ipv4/udp.c
    src/ipv4/icmp.c

    src/uv_lwip.c
)

add_executable(lan-play ${SOURCE_FILES})
target_link_libraries(lan-play lwip_lib ${PCAP_LIBRARY})
include_directories(lan-play ${PCAP_INCLUDE_DIR})

if (WIN32)
    add_dependencies(lan-play winpcap)
    target_link_libraries(lan-play libuv.a ws2_32.lib iphlpapi.lib libwinpthread.a psapi userenv.lib)
else()
    target_link_libraries(lan-play uv pthread)
endif()

INSTALL(TARGETS lan-play RUNTIME DESTINATION /usr/bin)
