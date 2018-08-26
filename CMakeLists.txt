cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)

if (WIN32)
    include(ExternalProject)
    ExternalProject_Add(
        winpcap
        PREFIX ${CMAKE_BINARY_DIR}/winpcap
        URL "https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip"
        CONFIGURE_COMMAND "" BUILD_COMMAND "" INSTALL_DIR "" INSTALL_COMMAND ""
        # LOG_DOWNLOAD ON
    )
    ExternalProject_Get_Property(winpcap SOURCE_DIR)
    set(PCAP_ROOT_DIR ${SOURCE_DIR})
    set(PCAP_INCLUDE_DIR ${SOURCE_DIR}/Include)
    set(PCAP_LIBRARY ${SOURCE_DIR}/Lib/wpcap.lib)
    message("PCAP_ROOT_DIR = ${PCAP_ROOT_DIR} INCLUDE = ${PCAP_INCLUDE_DIR}")
else()
    include(cmake/FindPCAP.cmake)
endif()

set(SOURCE_FILES
    src/main.c
    src/packet.c
    src/arp.c
    src/helper.c
    src/forwarder.c
    src/ipv4/ipv4.c
    src/ipv4/tcp.c
    src/ipv4/udp.c
    src/ipv4/icmp.c
)

add_executable (lan-play ${SOURCE_FILES})
target_link_libraries(lan-play ${PCAP_LIBRARY})
include_directories(lan-play ${PCAP_INCLUDE_DIR})
if (WIN32)
    add_dependencies(lan-play winpcap)
    target_link_libraries(lan-play ws2_32.lib iphlpapi.lib libwinpthread.a)
else()
    target_link_libraries(lan-play pthread)
endif()
