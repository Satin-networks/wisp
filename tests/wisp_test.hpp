#pragma once

#include <functional>
#include <string>
#include <vector>

namespace wisptest {

struct Case {
    std::string name;
    std::function<void()> fn;
};

std::vector<Case>& registry();

struct Registrar {
    Registrar(const char* name, std::function<void()> fn);
};

// Records a failure against the currently running case.
void record_failure(const std::string& message, const char* file, int line);

int run_all();

}  // namespace wisptest

#define WISP_TEST(test_name)                                                    \
    static void test_name();                                                    \
    static ::wisptest::Registrar registrar_##test_name(#test_name, test_name);  \
    static void test_name()

#define WISP_CHECK(cond)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            ::wisptest::record_failure("expected: " #cond, __FILE__, __LINE__);  \
        }                                                                       \
    } while (0)

#define WISP_CHECK_EQ(actual, expected)                                         \
    do {                                                                        \
        const auto& wisp_a = (actual);                                          \
        const auto& wisp_b = (expected);                                        \
        if (!(wisp_a == wisp_b)) {                                              \
            ::wisptest::record_failure(#actual " == " #expected, __FILE__,       \
                                       __LINE__);                               \
        }                                                                       \
    } while (0)
