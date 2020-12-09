function(test_single_c_file file)
    add_executable(chunk_${file} ${file}.c)
    target_link_libraries(chunk_${file} PRIVATE chunk)
    add_test(NAME chunk_${file} COMMAND chunk_${file})
endfunction()

test_single_c_file(leftover)
test_single_c_file(evenly)
test_single_c_file(finished)
