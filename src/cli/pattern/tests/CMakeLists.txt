function(test_single_c_file file)
    add_executable(cli_pattern_${file} ${file}.c)
    target_link_libraries(cli_pattern_${file} PRIVATE cli_pattern cli_parser)
    add_test(NAME cli_pattern_${file} COMMAND cli_pattern_${file})
endfunction()

test_single_c_file(invalid-patterns)
test_single_c_file(valid-patterns)
