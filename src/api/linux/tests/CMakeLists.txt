function(test_single_c_file file)
    add_executable(api_linux_${file} ${file}.c)
    target_link_libraries(api_linux_${file} PRIVATE api-static)
    add_test(NAME api_linux_${file} COMMAND api_linux_${file})
endfunction()

test_single_c_file(proc-path-size)

add_subdirectory(proc-maps)
