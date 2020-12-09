function(test_single_c_file file)
    add_executable(magic_${file} ${file}.c)
    add_test(NAME magic_${file} COMMAND magic_${file})
endfunction()

test_single_c_file(array-size)
test_single_c_file(compare)
test_single_c_file(deref)
