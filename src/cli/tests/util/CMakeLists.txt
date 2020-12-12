add_executable(proctal_sleeper sleeper.c)
always_build(proctal_sleeper)

add_executable(proctal_spit-back-mt spit-back-mt.c)
always_build(proctal_spit-back-mt)
target_link_libraries(proctal_spit-back-mt pthread)

add_executable(proctal_read-mem read-mem.c)
always_build(proctal_read-mem)

add_executable(proctal_read-mem-mt read-mem-mt.c)
target_link_libraries(proctal_read-mem-mt pthread)
always_build(proctal_read-mem-mt)
