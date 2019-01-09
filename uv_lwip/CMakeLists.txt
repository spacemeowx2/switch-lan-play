add_library(uv_lwip STATIC uv_lwip.c)
target_link_libraries(uv_lwip base lwip_lib)
target_link_libraries(uv_lwip base uv_a)
target_include_directories(lwip_lib PUBLIC .)
