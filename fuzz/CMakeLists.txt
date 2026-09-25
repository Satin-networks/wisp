# libFuzzer provides main(), so these targets must not link the test harness.
set(WISP_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -g)

foreach(fuzzer fuzz_config fuzz_netlink fuzz_ipc)
  add_executable(${fuzzer} ${fuzzer}.cpp)
  target_link_libraries(${fuzzer} PRIVATE wisp_core)
  target_compile_options(${fuzzer} PRIVATE ${WISP_FUZZ_FLAGS})
  target_link_options(${fuzzer} PRIVATE ${WISP_FUZZ_FLAGS})
endforeach()
