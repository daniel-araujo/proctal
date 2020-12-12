function(test_single_c_file file)
    add_executable(proctal_magic_${file} ${file}.c)
    add_test(NAME proctal_magic_${file} COMMAND proctal_magic_${file})
endfunction()

test_single_c_file(array-size)
test_single_c_file(compare)
test_single_c_file(deref)
