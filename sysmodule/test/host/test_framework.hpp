#pragma once

#include <cstdio>
#include <span>

namespace wgnx::test {

class TestContext {
public:
    explicit TestContext(const char *name) : m_name(name) {
    }

    void Fail(const char *expression, const char *file, int line, const char *detail = nullptr) {
        ++m_failure_count;
        std::fprintf(
            stderr,
            "  %s:%d: check failed: %s%s%s%s\n",
            file,
            line,
            expression,
            detail != nullptr ? " (" : "",
            detail != nullptr ? detail : "",
            detail != nullptr ? ")" : "");
    }

    bool Passed() const {
        return m_failure_count == 0;
    }

    const char *Name() const {
        return m_name;
    }

private:
    const char *m_name;
    unsigned int m_failure_count{0};
};

using TestFunction = void (*)(TestContext &context);

struct TestCase {
    const char *name;
    TestFunction run;
};

inline int RunTests(std::span<const TestCase> tests) {
    std::size_t failed = 0;
    for (const TestCase &test : tests) {
        TestContext context(test.name);
        test.run(context);
        if (context.Passed()) {
            std::printf("PASS %s\n", test.name);
        } else {
            std::printf("FAIL %s\n", test.name);
            ++failed;
        }
    }

    std::printf("RESULT passed=%zu failed=%zu total=%zu\n", tests.size() - failed, failed, tests.size());
    return failed == 0 ? 0 : 1;
}

} // namespace wgnx::test

#define WGNX_TEST_CHECK(context, expression) \
    do { \
        if (!(expression)) { \
            (context).Fail(#expression, __FILE__, __LINE__); \
            return; \
        } \
    } while (false)

#define WGNX_TEST_REQUIRE(context, expression, detail) \
    do { \
        if (!(expression)) { \
            (context).Fail(#expression, __FILE__, __LINE__, (detail)); \
            return; \
        } \
    } while (false)
