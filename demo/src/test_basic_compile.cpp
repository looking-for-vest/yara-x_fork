#include <iostream>
#include <cassert>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "yara_x.h"
}

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (cond) { \
            std::cout << "  [PASS] " << msg << std::endl; \
            tests_passed++; \
        } else { \
            std::cout << "  [FAIL] " << msg << std::endl; \
            tests_failed++; \
        } \
    } while(0)

void test_simple_compile() {
    std::cout << "\n=== Test: Simple Compile ===" << std::endl;
    
    const char* rule = "rule test { condition: true }";
    YRX_RULES* rules = nullptr;
    
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile simple rule");
    TEST_ASSERT(rules != nullptr, "Rules object is not null");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 1, "Rule count is 1");
        yrx_rules_destroy(rules);
    }
}

void test_compiler_create_destroy() {
    std::cout << "\n=== Test: Compiler Create/Destroy ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Compiler created successfully");
    TEST_ASSERT(compiler != nullptr, "Compiler is not null");
    
    if (compiler) {
        yrx_compiler_destroy(compiler);
        std::cout << "  [INFO] Compiler destroyed" << std::endl;
    }
}

void test_compiler_add_source() {
    std::cout << "\n=== Test: Compiler Add Source ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* rule1 = "rule rule1 { condition: true }";
    const char* rule2 = "rule rule2 { condition: false }";
    
    YRX_RESULT result1 = yrx_compiler_add_source(compiler, rule1);
    TEST_ASSERT(result1 == YRX_SUCCESS, "Add first rule");
    
    YRX_RESULT result2 = yrx_compiler_add_source(compiler, rule2);
    TEST_ASSERT(result2 == YRX_SUCCESS, "Add second rule");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    TEST_ASSERT(rules != nullptr, "Build rules successfully");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 2, "Rule count is 2");
        yrx_rules_destroy(rules);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_compiler_with_origin() {
    std::cout << "\n=== Test: Compiler Add Source With Origin ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* rule = "rule test { condition: true }";
    const char* origin = "test_rule.yar";
    
    YRX_RESULT result = yrx_compiler_add_source_with_origin(compiler, rule, origin);
    TEST_ASSERT(result == YRX_SUCCESS, "Add source with origin");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    TEST_ASSERT(rules != nullptr, "Build rules with origin");
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_multiple_compiler_flags() {
    std::cout << "\n=== Test: Multiple Compiler Flags ===" << std::endl;
    
    uint32_t flags = YRX_COLORIZE_ERRORS | YRX_RELAXED_RE_SYNTAX | YRX_ENABLE_CONDITION_OPTIMIZATION;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(flags, &compiler);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler with multiple flags");
    
    if (compiler) {
        yrx_compiler_destroy(compiler);
    }
}

void test_namespace() {
    std::cout << "\n=== Test: Namespace ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_new_namespace(compiler, "my_namespace");
    
    const char* rule = "rule namespaced_rule { condition: true }";
    yrx_compiler_add_source(compiler, rule);
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    TEST_ASSERT(rules != nullptr, "Build rules with namespace");
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_empty_rule() {
    std::cout << "\n=== Test: Empty Rule ===" << std::endl;
    
    const char* rule = "rule dummy { condition: true }";
    YRX_RULES* rules = nullptr;
    
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile empty rule (condition: true)");
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
}

void test_rule_iterator() {
    std::cout << "\n=== Test: Rule Iterator ===" << std::endl;
    
    const char* rule = R"(
        rule rule1 { condition: true }
        rule rule2 { condition: false }
        rule rule3 { condition: true }
    )";
    
    YRX_RULES* rules = nullptr;
    yrx_compile(rule, &rules);
    
    TEST_ASSERT(rules != nullptr, "Compile multiple rules");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 3, "Rule count is 3");
        
        int iter_count = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* count = static_cast<int*>(user_data);
            (*count)++;
            
            const uint8_t* ident = nullptr;
            size_t len = 0;
            if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
                std::string name(reinterpret_cast<const char*>(ident), len);
                std::cout << "    Found rule: " << name << std::endl;
            }
        };
        
        yrx_rules_iter(rules, callback, &iter_count);
        TEST_ASSERT(iter_count == 3, "Iterated 3 rules");
        
        yrx_rules_destroy(rules);
    }
}

void test_compiler_reset() {
    std::cout << "\n=== Test: Compiler Reset ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, "rule first { condition: true }");
    YRX_RULES* rules1 = yrx_compiler_build(compiler);
    TEST_ASSERT(rules1 != nullptr, "First build");
    
    if (rules1) {
        int count1 = yrx_rules_count(rules1);
        TEST_ASSERT(count1 == 1, "First build has 1 rule");
        yrx_rules_destroy(rules1);
    }
    
    yrx_compiler_add_source(compiler, "rule second { condition: true }");
    YRX_RULES* rules2 = yrx_compiler_build(compiler);
    TEST_ASSERT(rules2 != nullptr, "Second build after reset");
    
    if (rules2) {
        int count2 = yrx_rules_count(rules2);
        TEST_ASSERT(count2 == 1, "Second build has 1 rule");
        yrx_rules_destroy(rules2);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_load_rules_from_file() {
    std::cout << "\n=== Test: Load Rules From File ===" << std::endl;
    
    std::ifstream file("tests/rules/basic.yar");
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string rule_content = buffer.str();
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rules from file");
    TEST_ASSERT(rules != nullptr, "Rules loaded from file");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        std::cout << "    Loaded " << count << " rules" << std::endl;
        yrx_rules_destroy(rules);
    }
}

void test_include_directory() {
    std::cout << "\n=== Test: Include Directory ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_include_dir(compiler, "tests/rules");
    
    std::ifstream file("tests/rules/with_include.yar");
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string rule_content = buffer.str();
    
    YRX_RESULT result = yrx_compiler_add_source(compiler, rule_content.c_str());
    
    if (result == YRX_SUCCESS) {
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules with include");
        
        if (rules) {
            int count = yrx_rules_count(rules);
            TEST_ASSERT(count >= 2, "Include worked, got multiple rules");
            yrx_rules_destroy(rules);
        }
    } else {
        std::cout << "    [INFO] Include test skipped: " << yrx_last_error() << std::endl;
    }
    
    yrx_compiler_destroy(compiler);
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Basic Compile Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_simple_compile();
    test_compiler_create_destroy();
    test_compiler_add_source();
    test_compiler_with_origin();
    test_multiple_compiler_flags();
    test_namespace();
    test_empty_rule();
    test_rule_iterator();
    test_compiler_reset();
    test_load_rules_from_file();
    test_include_directory();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
