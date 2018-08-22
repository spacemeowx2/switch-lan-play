cmake_minimum_required(VERSION 3.0)
project (SwitchLanPlay)

set(CMAKE_CXX_STANDARD 11)

include(cmake/FindPCAP.cmake)

set(SOURCE_FILES src/main.cpp)

add_executable (lan-play ${SOURCE_FILES})
target_link_libraries(lan-play ${PCAP_LIBRARY})
