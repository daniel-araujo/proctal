function(test_single_c_file file)
    add_executable(proctal_api_linux_proc_maps_${file} ${file}.c)
    target_link_libraries(proctal_api_linux_proc_maps_${file} PRIVATE proctal_api-static)
    add_test(NAME proctal_api_linux_proc_maps_${file} COMMAND proctal_api_linux_proc_maps_${file})
endfunction()

test_single_c_file(check)
test_single_c_file(correct-properties)
