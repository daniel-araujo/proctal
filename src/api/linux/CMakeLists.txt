add_subdirectory(tests)

add_library(
    proctal_api_linux

    OBJECT

    implementation.c
    address.c
    address.h
    region.c
    region.h
    allocate.c
    allocate.h
    execute.h
    execute/implementation.h
    execute/interface.c
    mem.c
    mem.h
    proc-maps.c
    proc.c
    proc.h
    ptrace.h
    ptrace/error-checking.c
    ptrace/implementation.h
    ptrace/interface.c
    ptrace/internal.h
    proctal.c
    proctal.h
    watch/interface.c
    watch/implementation.h
    watch.h
)

if(PROCTAL_SHARED)
    # Code needs to be compiled with position independent instructions.
    set_property(TARGET proctal_api_linux PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

target_link_libraries(proctal_api_linux proctal_api_darr)
target_link_libraries(proctal_api_linux proctal_api_acur)

if(PROCTAL_CPU_ARCHITECTURE_X86 AND PROCTAL_CPU_ARCHITECTURE_X86_MODE_64)
    target_SOURCES(
        proctal_api_linux

        PRIVATE

        ptrace/implementation/x86_64/cpu-state.c
        ptrace/implementation/x86_64/instruction-pointer.c
        ptrace/implementation/x86_64/register.c
        ptrace/user-register.c

        execute/x86_64/no-op-code.c
        execute/x86_64/syscall.c
        execute/x86_64/trap-code.c
        execute/x86_64/savestate.c
        execute/x86_64/stackframe.c
        execute/hijack-main.c

        watch/x86_64/breakpoint.c
    )
else()
    target_SOURCES(
        proctal_api_linux

        PRIVATE

        ptrace/implementation/unsupported/cpu-state.c
        ptrace/implementation/unsupported/instruction-pointer.c
        ptrace/implementation/unsupported/register.c

        execute/unimplemented.c

        watch/unimplemented.c
    )
endif()
