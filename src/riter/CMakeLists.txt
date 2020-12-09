add_library(riter STATIC riter.c riter.h)

target_link_libraries(riter PRIVATE swbuf)
target_link_libraries(riter PRIVATE chunk)

add_subdirectory(tests)
