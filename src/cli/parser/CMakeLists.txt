make_php_c(names.c.php)

add_library(
    cli_parser

    OBJECT

    parser.h
    c-types.c
    names.c
    skip.c
    hex.c
)
