add_executable(wispd main.cpp)

target_link_libraries(wispd PRIVATE wisp_core)

install(TARGETS wispd RUNTIME DESTINATION bin)
