
message(STATUS "Installing libuv via submodule")
execute_process(COMMAND git submodule update --init -- external/libuv
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(external/libuv EXCLUDE_FROM_ALL)
target_include_directories(uv_a INTERFACE external/libuv/include)

message(STATUS "Installing uvw via submodule")
execute_process(COMMAND git submodule update --init -- external/uvw
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(external/uvw EXCLUDE_FROM_ALL)
include_directories(external/uvw/src)
