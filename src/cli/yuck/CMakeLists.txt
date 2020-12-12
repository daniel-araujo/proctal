m4_preprocess(args.yuck.m4)
yuck_compile(args.yuck)
yuck_manpage(proctal.1 args.yuck)

add_custom_target(proctal_compile_yuck ALL DEPENDS args.yucc proctal.1)

add_library(
    proctal_cli_yuck

    OBJECT

    main.h
    main.c
)

add_dependencies(proctal_cli_yuck proctal_compile_yuck)

target_link_libraries(proctal_cli_yuck darr)
