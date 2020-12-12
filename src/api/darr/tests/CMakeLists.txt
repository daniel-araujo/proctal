add_subdirectory(util)

function(test_single_c_file file)
    add_executable(proctal_api_darr_${file} ${file}.c)
    target_link_libraries(proctal_api_darr_${file} PRIVATE proctal_api-static proctal_api_darr_block-size)
    add_test(NAME proctal_api_darr_${file} COMMAND proctal_api_darr_${file})
endfunction()

test_single_c_file(realloc-decrease-size-new-block)
test_single_c_file(realloc-decrease-size-same-block)
test_single_c_file(realloc-increase-size-new-block)
test_single_c_file(realloc-null-argument)
