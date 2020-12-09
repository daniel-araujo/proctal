add_executable(sleeper sleeper.c)
always_build(sleeper)

add_executable(spit-back-mt spit-back-mt.c)
always_build(spit-back-mt)
target_link_libraries(spit-back-mt pthread)

add_executable(read-mem read-mem.c)
always_build(read-mem)

add_executable(read-mem-mt read-mem-mt.c)
target_link_libraries(read-mem-mt pthread)
always_build(read-mem-mt)
