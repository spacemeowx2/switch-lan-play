set(BASE_SOURCES
    debug.c
    llog.c
)
add_library(base STATIC ${BASE_SOURCES})
target_include_directories(base PUBLIC include)
