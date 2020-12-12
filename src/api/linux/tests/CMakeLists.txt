function(test_single_c_file file)
    add_executable(proctal_api_linux_${file} ${file}.c)
    target_link_libraries(proctal_api_linux_${file} PRIVATE proctal_api-static)
    add_test(NAME proctal_api_linux_${file} COMMAND proctal_api_linux_${file})
endfunction()

test_single_c_file(proc-path-size)

add_subdirectory(proc-maps)
