add_executable(wisp_bench bench_main.cpp)
target_link_libraries(wisp_bench PRIVATE wisp_core)

# Still buildable under sanitizers - it is a useful extra correctness pass - but
# say so out loud, because every number it prints will be dominated by
# instrumentation rather than by the code.
if(WISP_SANITIZE)
  message(STATUS "wisp_bench will be instrumented; its timings will not be representative")
endif()
