make_php_c(names.c.php)

add_library(
    proctal_cli_parser

    OBJECT

    parser.h
    c-types.c
    names.c
    skip.c
    hex.c
)
