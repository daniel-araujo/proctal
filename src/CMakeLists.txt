# Generates a header file that can contain values of CMake variables.
configure_file(config.h.in config.h ESCAPE_QUOTES @ONLY)

# So that generated files can be included.
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# The include statement will be relative to the src directory.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# General compilation options
set_property(DIRECTORY PROPERTY C_STANDARD 11)

if (MSVC)
    # I have yet to test this on Windows.

    add_compile_options(/W4 /WX)

    add_compile_options(
        -DNTDDI_VERSION=NTDDI_WINXPSP2
    )
else()
    # Assuming to be GCC compatible.

    # Make the compiler less forgiving.
    add_compile_options(
        -Wall
        -Wextra
        -Wfatal-errors
        -Wpointer-arith
    )

    # Turn warnings into error messages.
    add_compile_options(
        -Werror=incompatible-pointer-types
    )

    # Suppress less desirable warning messages.
    add_compile_options(
        -Wno-unused-variable
        -Wno-unused-label
        -Wno-unused-function
        -Wno-unused-parameter
    )

    # Make ssize_t available in C11 mode.
    add_definitions(-D_XOPEN_SOURCE=500)

    # Make usleep available.
    add_definitions(-D_POSIX_C_SOURCE=200112L)

    # Let glibc declare syscall.
    add_definitions(-D_DEFAULT_SOURCE)
endif()

# Let each module build their targets.
add_subdirectory(api)
add_subdirectory(chunk)
add_subdirectory(cli)
add_subdirectory(magic)
add_subdirectory(otrap)
add_subdirectory(pq)
add_subdirectory(riter)
add_subdirectory(swbuf)
