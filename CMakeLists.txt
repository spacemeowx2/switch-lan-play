cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)

include(cmake/FindPCAP.cmake)

set(SOURCE_FILES src/main.c src/packet.c src/arp.c src/helper.c src/ipv4)

add_executable (lan-play ${SOURCE_FILES})
target_link_libraries(lan-play ${PCAP_LIBRARY})
