###############################################################################
# Project definition and settings
###############################################################################

cmake_minimum_required(VERSION 3.14)

project(Proctal VERSION 0)

enable_testing()

# Platform check.
if(UNIX AND NOT APPLE)
    set(PROCTAL_PLATFORM_LINUX ON)
elseif(WIN32)
    set(PROCTAL_PLATFORM_WINDOWS ON)
else()
    set(PROCTAL_PLATFORM_UNKNOWN ON)
    message(WARNING "Could not detect platform")
endif()

# Architecture check.
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL x86_64 OR CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL amd64)
    set(PROCTAL_CPU_ARCHITECTURE_X86 ON)
    set(PROCTAL_CPU_ARCHITECTURE_X86_MODE_64 ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES arm.*)
    set(PROCTAL_CPU_ARCHITECTURE_ARM ON)
    set(PROCTAL_CPU_ARCHITECTURE_ARM_MODE_A32 ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL aarch64)
    set(PROCTAL_CPU_ARCHITECTURE_ARM ON)
    set(PROCTAL_CPU_ARCHITECTURE_ARM_MODE_64 ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES i[3456]86)
    set(PROCTAL_CPU_ARCHITECTURE_X86 ON)
    set(PROCTAL_CPU_ARCHITECTURE_X86_MODE_32 ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL sparc)
    set(PROCTAL_CPU_ARCHITECTURE_SPARC ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES powerpc.*)
    set(PROCTAL_CPU_ARCHITECTURE_POWERPC ON)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL mips)
    set(PROCTAL_CPU_ARCHITECTURE_MIPS ON)
else()
    set(PROCTAL_CPU_ARCHITECTURE_UNKNOWN ON)
    message(WARNING "Could not detect architecture")
endif()

# Endianness check.
include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    set(PROCTAL_INTEGER_ENDIANNESS_BIG ON)
else()
    set(PROCTAL_INTEGER_ENDIANNESS_LITTLE ON)
endif()

# Whether to build static library.
option(BUILD_STATIC_LIBS "Build static library" ON)
if(BUILD_STATIC_LIBS)
    set(PROCTAL_STATIC ON)
endif()
# Our dependencies are included as subdirectories. We always want them to be
# built as static libraries.
set(BUILD_STATIC_LIBS ON)

# Whether to build shared library.
option(BUILD_SHARED_LIBS "Build shared library" OFF)
if(BUILD_SHARED_LIBS)
    set(PROCTAL_SHARED ON)

    # Our dependencies are included as subdirectories. We don't want to
    # propagate this setting to them.
    set(BUILD_SHARED_LIBS FALSE)
endif()

# Dependency options.
set(CAPSTONE_GIT "https://github.com/aquynh/capstone.git" CACHE STRING "capstone git repository")
set(KEYSTONE_GIT "https://github.com/keystone-engine/keystone.git" CACHE STRING "keystone git repository")
set(DARR_GIT "https://github.com/daniel-araujo/darr.git" CACHE STRING "darr git repository")
set(ACUR_GIT "https://github.com/daniel-araujo/acur.git" CACHE STRING "acur git repository")
set(YUCK_GIT "https://github.com/hroptatyr/yuck.git" CACHE STRING "yuck git repository")
set(PHP "php" CACHE STRING "Path to php interpreter")
set(M4 "m4" CACHE STRING "Path to m4 command")
set(SED "sed" CACHE STRING "Path to sed command")
set(PYTHON "python3" CACHE STRING "Path to python3 command")

message(STATUS "KEYSTONE_GIT = ${KEYSTONE_GIT}")
message(STATUS "CAPSTONE_GIT = ${CAPSTONE_GIT}")
message(STATUS "DARR_GIT = ${DARR_GIT}")
message(STATUS "ACUR_GIT = ${ACUR_GIT}")
message(STATUS "YUCK_GIT = ${YUCK_GIT}")
message(STATUS "PHP = ${PHP}")
message(STATUS "M4 = ${M4}")
message(STATUS "SED = ${SED}")
message(STATUS "PYTHON = ${PYTHON}")





###############################################################################
# Dependencies
###############################################################################

include(ExternalProject)
include(FetchContent)

# Keystone
if(CMAKE_BUILD_TYPE STREQUAL Release)
    find_library(KEYSTONE_LIBRARY keystone)

    if(KEYSTONE_LIBRARY)
        message(STATUS "Found keystone library. Will link to it.")
        set(PROCTAL_KEYSTONE ON)
    else()
        message(STATUS "Keystone library not found. Some features will be missing.")
    endif()
else()
    message(STATUS "Fetching keystone")
    FetchContent_Declare(
        keystone_project

        GIT_REPOSITORY
            ${KEYSTONE_GIT}
        GIT_TAG
            0.9.2
    )
    FetchContent_Populate(keystone_project)
    add_subdirectory(${keystone_project_SOURCE_DIR} ${keystone_project_BINARY_DIR} EXCLUDE_FROM_ALL)
    include_directories(${keystone_project_SOURCE_DIR}/include)

    set(PROCTAL_KEYSTONE ON)
endif()

# Capstone
if(CMAKE_BUILD_TYPE STREQUAL Release)
    find_library(CAPSTONE_LIBRARY capstone)

    if(CAPSTONE_LIBRARY)
        message(STATUS "Found capstone library. Will link to it.")
        set(PROCTAL_CAPSTONE ON)
    else()
        message(STATUS "Capstone library not found. Some features will be missing.")
    endif()
else()
    message(STATUS "Capstone repository set. Will compile from source")

    FetchContent_Declare(
        capstone_project

        GIT_REPOSITORY
            ${CAPSTONE_GIT}
        GIT_TAG
            4.0.2
    )
    FetchContent_Populate(capstone_project)
    add_subdirectory(${capstone_project_SOURCE_DIR} ${capstone_project_BINARY_DIR} EXCLUDE_FROM_ALL)
    include_directories(${capstone_project_SOURCE_DIR}/include)

    set(PROCTAL_CAPSTONE ON)
endif()

# Acur
message(STATUS "Fetching acur")
FetchContent_Declare(
    acur_project

    GIT_REPOSITORY
        ${ACUR_GIT}
    GIT_TAG
        v1.1.3
)
FetchContent_Populate(acur_project)
add_subdirectory(${acur_project_SOURCE_DIR} ${acur_project_BINARY_DIR} EXCLUDE_FROM_ALL)

# Darr
message(STATUS "Fetching darr")
FetchContent_Declare(
    darr_project

    GIT_REPOSITORY
        ${DARR_GIT}
    GIT_TAG
        351c3a07eb30706448307079b39aafd540cda8de
)
FetchContent_Populate(darr_project)
add_subdirectory(${darr_project_SOURCE_DIR} ${darr_project_BINARY_DIR} EXCLUDE_FROM_ALL)

# Yuck
if(NOT DEFINED YUCK)
    message(STATUS "Fetching yuck")

    FetchContent_Declare(
        yuck_project
    
        GIT_REPOSITORY
            ${YUCK_GIT}
        GIT_TAG
            b4f944164bca2d9a3905a9a36944ab33ba19201f
        PATCH_COMMAND
            autoreconf -i
    )
    FetchContent_Populate(yuck_project)

    execute_process(
        COMMAND
            ${yuck_project_SOURCE_DIR}/configure --prefix=${yuck_project_INSTALL_DIR}
        WORKING_DIRECTORY
            ${yuck_project_BINARY_DIR}
        RESULT_VARIABLE
            ret
    )

    if(NOT ret EQUAL 0)
        message(FATAL_ERROR "Failed to configure yuck build")
    endif()

    execute_process(
        COMMAND
            make
        WORKING_DIRECTORY
            ${yuck_project_BINARY_DIR}
        RESULT_VARIABLE
            ret
    )

    if(NOT ret EQUAL 0)
        message(FATAL_ERROR "Failed to build yuck")
    endif()

    set(YUCK ${yuck_project_BINARY_DIR}/src/yuck)
endif()





###############################################################################
# Utilities
###############################################################################

function(make_php_c source_file)
    get_filename_component(output_file ${source_file} NAME_WLE)
    relative_build_or_source(source_file ${source_file})

    add_custom_command(
        OUTPUT
            ${output_file}
        COMMAND
            ${PHP} ${source_file} > ${output_file}
        MAIN_DEPENDENCY
            ${source_file}
        VERBATIM
    )
endfunction()

function(naive_prefix_funcs output_file source_file prefix)
    relative_build_or_source(source_file ${source_file})

    add_custom_command(
        OUTPUT
            ${output_file}
        COMMAND
            ${SED} s/${prefix}_/proctal_${prefix}_/g ${source_file} > ${output_file}
        COMMAND
            ${SED} -i "s/struct ${prefix}/struct proctal_${prefix}/g" ${output_file}
        MAIN_DEPENDENCY
            ${source_file}
        VERBATIM
    )
endfunction()

function(yuck_compile source_file)
    get_filename_component(output_file ${source_file} NAME_WLE)
    set(output_file ${output_file}.yucc)
    relative_build_or_source(source_file ${source_file})

    add_custom_command(
        OUTPUT
            ${output_file}
        COMMAND
            ${YUCK} gen --no-auto-flags --no-auto-actions ${source_file} -o ${output_file}
        MAIN_DEPENDENCY
            ${source_file}
        VERBATIM
    )
endfunction()

function(yuck_manpage output_file source_file)
    relative_build_or_source(source_file ${source_file})

    add_custom_command(
        OUTPUT
            ${output_file}
        COMMAND
            ${YUCK} genman ${source_file} -o ${output_file}
        MAIN_DEPENDENCY
            ${source_file}
        VERBATIM
    )
endfunction()

function(m4_preprocess source_file)
    get_filename_component(output_file ${source_file} NAME_WLE)
    relative_build_or_source(source_file ${source_file})

    add_custom_command(
        OUTPUT
            ${output_file}
        COMMAND
            ${M4} ${source_file} > ${output_file}
        MAIN_DEPENDENCY
            ${source_file}
        VERBATIM
    )
endfunction()

function(relative_build_or_source var file_name)
    cmake_parse_arguments(
        PARSE_ARGV
        2
        relative_build_or_source
        "REQUIRED"
        ""
        ""
    )

    set(source_file "${CMAKE_CURRENT_BINARY_DIR}/${file_name}")
    set(binary_file "${CMAKE_CURRENT_SOURCE_DIR}/${file_name}")

    if("${file_name}" MATCHES "^/.*")
        set(${var} "${file_name}" PARENT_SCOPE)
    elseif(TARGET "${file_name}")
        set(${var} "${binary_file}" PARENT_SCOPE)
    elseif(EXISTS "${binary_file}")
        set(${var} "${binary_file}" PARENT_SCOPE)
    elseif(EXISTS "${source_file}")
        set(${var} "${source_file}" PARENT_SCOPE)
    elseif(relative_build_or_source_REQUIRED)
        message(FATAL_ERROR "${file_name} not found in ${CMAKE_CURRENT_BINARY_DIR} nor ${CMAKE_CURRENT_SOURCE_DIR}")
    else()
        set(${var} "${file_name}" PARENT_SCOPE)
    endif()
endfunction()

function(always_build other_target)
    if(NOT TARGET always_build_dummy_target)
        add_custom_target(always_build_dummy_target ALL)
    endif()

    add_dependencies(always_build_dummy_target ${other_target})
endfunction()





###############################################################################
# Build & Install
###############################################################################

add_subdirectory(src)

install(TARGETS cli)

if(PROCTAL_SHARED)
    install(TARGETS api-shared)
endif()

if(PROCTAL_STATIC)
    install(TARGETS api-static)
endif()

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/src/cli/yuck/proctal.1
    DESTINATION
        share/man/man1
)

set(CPACK_PACKAGE_HOMEPAGE_URL "https://proctal.io")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.rst")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
include(CPack)
