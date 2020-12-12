add_library(
    proctal_cli_assembler

    OBJECT

    assembler.h
    internal.h
    internal.c
    interface.c
    implementation.h
    implementation.c
)

if(PROCTAL_CAPSTONE)
    if(CAPSTONE_LIBRARY)
        target_link_libraries(proctal_cli_assembler capstone)
    else()
        # Has different name.
        target_link_libraries(proctal_cli_assembler capstone-static)
    endif()
endif()

if(PROCTAL_KEYSTONE)
    target_link_libraries(proctal_cli_assembler keystone)
endif()
