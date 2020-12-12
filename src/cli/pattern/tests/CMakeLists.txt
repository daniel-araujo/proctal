function(test_single_c_file file)
    add_executable(proctal_cli_pattern_${file} ${file}.c)
    target_link_libraries(proctal_cli_pattern_${file} PRIVATE proctal_cli_pattern proctal_cli_parser)
    add_test(NAME proctal_cli_pattern_${file} COMMAND proctal_cli_pattern_${file})
endfunction()

test_single_c_file(invalid-patterns)
test_single_c_file(valid-patterns)
