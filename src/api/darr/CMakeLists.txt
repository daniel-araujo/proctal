add_subdirectory(tests)

naive_prefix_funcs(darr.h ${proctal_darr_project_SOURCE_DIR}/src/darr.h darr)
naive_prefix_funcs(darr.c ${proctal_darr_project_SOURCE_DIR}/src/darr.c darr)

add_library(
    proctal_api_darr

    OBJECT

    memory-support.h
    memory-support.c
    darr.h
    darr.c
)

if(PROCTAL_SHARED)
    # Code needs to be compiled with position independent instructions.
    set_property(TARGET proctal_api_darr PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
