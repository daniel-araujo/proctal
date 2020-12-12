function(test_single_c_file file)
    add_executable(proctal_chunk_${file} ${file}.c)
    target_link_libraries(proctal_chunk_${file} PRIVATE proctal_chunk)
    add_test(NAME proctal_chunk_${file} COMMAND proctal_chunk_${file})
endfunction()

test_single_c_file(leftover)
test_single_c_file(evenly)
test_single_c_file(finished)
