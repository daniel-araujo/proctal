naive_prefix_funcs(acur.h ${proctal_acur_project_SOURCE_DIR}/src/acur.h acur)
naive_prefix_funcs(acur.c ${proctal_acur_project_SOURCE_DIR}/src/acur.c acur)

add_library(
    proctal_api_acur

    OBJECT

    acur.h
    acur.c
)

if(PROCTAL_SHARED)
    # Code needs to be compiled with position independent instructions.
    set_property(TARGET proctal_api_acur PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
