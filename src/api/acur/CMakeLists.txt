naive_prefix_funcs(acur.h ${acur_project_SOURCE_DIR}/src/acur.h acur)
naive_prefix_funcs(acur.c ${acur_project_SOURCE_DIR}/src/acur.c acur)

add_library(
    api_acur

    OBJECT

    acur.h
    acur.c
)

if(PROCTAL_SHARED)
    # Code needs to be compiled with position independent instructions.
    set_property(TARGET api_acur PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
