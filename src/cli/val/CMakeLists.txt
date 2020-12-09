add_subdirectory(tests)

add_library(
    cli_val

    OBJECT

    integer.h
    integer.c
    integer-sign-unsigned.c
    integer-sign-signed.c
    integer-endianness.c
    ieee754.h
    ieee754.c
    address.h
    address.c
    byte.h
    byte.c
    text.h
    text.c
    text-encoding-ascii.c
    assembler.h
    assembler.c
    filter.h
    filter.c
    x86.h
    x86.c
    arm.h
    arm.c
    sparc.h
    sparc.c
    powerpc.h
    powerpc.c
    mips.h
    mips.c
    val.h
    val.c
)
