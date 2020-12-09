function(test_single_c_file file)
    add_executable(api_linux_proc_maps_${file} ${file}.c)
    target_link_libraries(api_linux_proc_maps_${file} PRIVATE api-static)
    add_test(NAME api_linux_proc_maps_${file} COMMAND api_linux_proc_maps_${file})
endfunction()

test_single_c_file(check)
test_single_c_file(correct-properties)
