add_subdirectory(val)
add_subdirectory(assembler)
add_subdirectory(yuck)
add_subdirectory(parser)
add_subdirectory(pattern)
add_subdirectory(tests)

add_executable(
    cli

    cmd/allocate.c
    cmd/allocate.h
    cmd/deallocate.c
    cmd/deallocate.h
    cmd/execute.c
    cmd/execute.h
    cmd/watch.c
    cmd/watch.h
    cmd/pause.c
    cmd/pause.h
    cmd/read.c
    cmd/read.h
    cmd/write.c
    cmd/write.h
    cmd/search.c
    cmd/search.h
    cmd/pattern.c
    cmd/pattern.h
    cmd/measure.c
    cmd/measure.h
    cmd/dump.c
    cmd/dump.h
    scanner.h
    scanner.c
    printer.h
    printer.c
    vmagazine.h
    vmagazine.c
    main.c
)

set_target_properties(cli PROPERTIES OUTPUT_NAME "proctal")

target_link_libraries(cli api-static)
target_link_libraries(cli pq)
target_link_libraries(cli chunk)
target_link_libraries(cli swbuf)
target_link_libraries(cli riter)
target_link_libraries(cli cli_val)
target_link_libraries(cli cli_assembler)
target_link_libraries(cli cli_yuck)
target_link_libraries(cli cli_parser)
target_link_libraries(cli cli_pattern)
