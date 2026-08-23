add_executable(proctal_sleeper sleeper.c)
always_build(proctal_sleeper)
set_target_properties(proctal_sleeper PROPERTIES OUTPUT_NAME "sleeper")

add_executable(proctal_spit-back-mt spit-back-mt.c)
always_build(proctal_spit-back-mt)
target_link_libraries(proctal_spit-back-mt pthread)
set_target_properties(proctal_spit-back-mt PROPERTIES OUTPUT_NAME "spit-back-mt")

add_executable(proctal_read-mem read-mem.c)
always_build(proctal_read-mem)
set_target_properties(proctal_read-mem PROPERTIES OUTPUT_NAME "read-mem")

add_executable(proctal_read-mem-mt read-mem-mt.c)
target_link_libraries(proctal_read-mem-mt pthread)
always_build(proctal_read-mem-mt)
set_target_properties(proctal_read-mem-mt PROPERTIES OUTPUT_NAME "read-mem-mt")
