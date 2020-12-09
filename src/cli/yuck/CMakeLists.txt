m4_preprocess(args.yuck.m4)
yuck_compile(args.yuck)
yuck_manpage(proctal.1 args.yuck)

add_custom_target(compile_yuck ALL DEPENDS args.yucc proctal.1)

add_library(
    cli_yuck

    OBJECT

    main.h
    main.c
)

add_dependencies(cli_yuck compile_yuck)

target_link_libraries(cli_yuck darr)
