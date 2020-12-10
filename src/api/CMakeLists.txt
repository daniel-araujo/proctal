add_subdirectory(darr)
add_subdirectory(acur)

make_php_c(error-message.c.php)

# The static version of the library is always built. It will be linked into
# the shared version.
add_library(
    api-static

    STATIC

    implementation.h
    proctal.h
    version.c
    error.c
    error-message.c
    watch.c
    pause.c
    write.c
    read.c
    address.c
    region.c
    allocate.c
    execute.c
    malloc.c
    global.c
    proc.c
    handle.c
)

set_target_properties(api-static PROPERTIES OUTPUT_NAME "proctal")
set_target_properties(api-static PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/proctal.h")

if(PROCTAL_SHARED)
    # Code needs to be compiled with position independent instructions.
    set_property(TARGET api-static PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

target_link_libraries(api-static api_darr)
target_link_libraries(api-static api_acur)

if(PROCTAL_PLATFORM_LINUX)
    add_subdirectory(linux)
    target_link_libraries(api-static api_linux)
elseif(PROCTAL_PLATFORM_WINDOWS)
    add_subdirectory(windows)
    target_link_libraries(api-static api_windows)
else()
    target_SOURCES(api-static PRIVATE unimplemented.c)
endif()

if(PROCTAL_CPU_ARCHITECTURE_X86 AND PROCTAL_CPU_ARCHITECTURE_X86_MODE_64)
    target_SOURCES(api-static PRIVATE x86_64/dr.c x86_64/dr.h)
endif()

if(PROCTAL_SHARED)
    # Libraries need at least 1 source file.
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/cmake-no-source-workaround.c "")
    add_library(api-shared SHARED ${CMAKE_CURRENT_BINARY_DIR}/cmake-no-source-workaround.c)
    set_target_properties(api-shared PROPERTIES OUTPUT_NAME "proctal")
    set_target_properties(api-shared PROPERTIES PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/proctal.h")
    target_link_libraries(api-shared api-static)
endif()
