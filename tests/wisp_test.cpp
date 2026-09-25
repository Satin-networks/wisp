#include "wisp_test.hpp"

#include <exception>
#include <iostream>
#include <string>

namespace wisptest {
namespace {
int g_failures_in_case = 0;
}  // namespace

std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

Registrar::Registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
}

void record_failure(const std::string& message, const char* file, int line) {
    ++g_failures_in_case;
    std::cerr << "    FAIL " << file << ":" << line << ": " << message << "\n";
}

int run_all() {
    int failed_cases = 0;
    for (auto& test_case : registry()) {
        g_failures_in_case = 0;
        std::cout << "[ RUN  ] " << test_case.name << "\n";
        try {
            test_case.fn();
        } catch (const std::exception& e) {
            record_failure(std::string("threw exception: ") + e.what(), __FILE__, __LINE__);
        } catch (...) {
            record_failure("threw a non-standard exception", __FILE__, __LINE__);
        }

        if (g_failures_in_case == 0) {
            std::cout << "[  OK  ] " << test_case.name << "\n";
        } else {
            std::cout << "[ FAIL ] " << test_case.name << "\n";
            ++failed_cases;
        }
    }

    std::cout << "\n" << registry().size() << " cases run, " << failed_cases << " failed\n";
    return failed_cases == 0 ? 0 : 1;
}

}  // namespace wisptest
