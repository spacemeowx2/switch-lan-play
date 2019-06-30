execute_process(COMMAND git describe --tags
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE LANPLAY_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

if (LANPLAY_VERSION STREQUAL "")
    set(LANPLAY_VERSION v0.1.0)
    MESSAGE("git describe --tags output is empty, set version to ${LANPLAY_VERSION}")
endif()

set(src
    main.c
    lan-play.c
    rpc.cpp
    pcaploop.c
    packet.c
    arp.c
    helper.c
    lan-client.c
    gateway.cpp
    proxy_direct.cpp
    proxy_socks5.cpp
    ipv4/ipv4.c
    ipv4/tcp.c
    ipv4/udp.c
    ipv4/icmp.c
)

add_executable(lan-play ${src})

target_compile_options(
    lan-play
    PRIVATE "-DLANPLAY_VERSION=\"${LANPLAY_VERSION}\""
)
if (${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
    target_compile_options(
        lan-play
        PRIVATE "-Wall"
        PRIVATE "-Wno-unused-function"
    )
endif()

set_target_properties(lan-play PROPERTIES CXX_STANDARD 17)

target_link_libraries(lan-play base)
target_link_libraries(lan-play uv_lwip)
target_link_libraries(lan-play uv_a)

find_package(PCAP REQUIRED)
target_link_libraries(lan-play ${PCAP_LIBRARY})
target_include_directories(lan-play PRIVATE ${PCAP_INCLUDE_DIR})

if (WIN32)
    add_dependencies(lan-play winpcap)
    target_link_libraries(lan-play ws2_32.lib iphlpapi.lib psapi userenv.lib)
    # https://stackoverflow.com/questions/13768515/how-to-do-static-linking-of-libwinpthread-1-dll-in-mingw
    target_link_libraries(lan-play -static-libgcc -static-libstdc++ -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic)
else()
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
        target_link_libraries(lan-play pthread)
    endif()
endif()

INSTALL(TARGETS lan-play RUNTIME DESTINATION bin)
