add_library(proctal_riter STATIC riter.c riter.h)

target_link_libraries(proctal_riter PRIVATE proctal_swbuf)
target_link_libraries(proctal_riter PRIVATE proctal_chunk)

add_subdirectory(tests)
