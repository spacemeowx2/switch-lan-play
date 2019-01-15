option(UV_LIBRARY "use installed libuv instead of building from source")
option(UVW_LIBRARY "use installed uvw instead of building from source")

if (UV_LIBRARY)
    find_package(Libuv REQUIRED)
    add_library(uv_a STATIC IMPORTED)
    set_target_properties(uv_a PROPERTIES
        IMPORTED_LOCATION ${LIBUV_LIBRARIES}
        INTERFACE_INCLUDE_DIRECTORIES ${LIBUV_INCLUDE_DIR}
    )
else()
    message(STATUS "Installing libuv via submodule")
    execute_process(COMMAND git submodule update --init -- external/libuv
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_subdirectory(external/libuv EXCLUDE_FROM_ALL)
    target_include_directories(uv_a INTERFACE external/libuv/include)
endif()

if (UVW_LIBRARY)
    find_package(UVW REQUIRED)
    add_library(uvw STATIC IMPORTED)
    set_target_properties(uvw PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${LIBUVW_INCLUDE_DIR}
    )
else()
    message(STATUS "Installing uvw via submodule")
    execute_process(COMMAND git submodule update --init -- external/uvw
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_subdirectory(external/uvw EXCLUDE_FROM_ALL)
    include_directories(external/uvw/src)
endif()
