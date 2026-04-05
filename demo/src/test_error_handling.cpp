#include <iostream>
#include <cassert>
#include <cstring>
#include <string>

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

void test_syntax_error() {
    std::cout << "\n=== Test: Syntax Error ===" << std::endl;
    
    const char* invalid_rule = R"(
        rule invalid {
            strings:
                $a = "test
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(invalid_rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Syntax error detected");
    TEST_ASSERT(rules == nullptr, "Rules is null on syntax error");
    
    const char* error = yrx_last_error();
    TEST_ASSERT(error != nullptr, "Error message is not null");
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}

void test_unknown_identifier() {
    std::cout << "\n=== Test: Unknown Identifier ===" << std::endl;
    
    const char* rule = R"(
        rule unknown_id {
            condition:
                undefined_var
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Unknown identifier error");
    
    const char* error = yrx_last_error();
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}

void test_invalid_regex() {
    std::cout << "\n=== Test: Invalid Regex ===" << std::endl;
    
    const char* rule = R"(
        rule bad_regex {
            strings:
                $re = /unclosed[/
            condition:
                $re
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Invalid regex error");
    
    const char* error = yrx_last_error();
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}

void test_invalid_hex_pattern() {
    std::cout << "\n=== Test: Invalid Hex Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule bad_hex {
            strings:
                $hex = { GG HH }
            condition:
                $hex
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Invalid hex pattern error");
    
    const char* error = yrx_last_error();
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}

void test_duplicate_rule_name() {
    std::cout << "\n=== Test: Duplicate Rule Name ===" << std::endl;
    
    const char* rule = R"(
        rule duplicate { condition: true }
        rule duplicate { condition: false }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Duplicate rule name error");
    
    const char* error = yrx_last_error();
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}

void test_invalid_argument_null_compiler() {
    std::cout << "\n=== Test: Invalid Argument - Null Compiler ===" << std::endl;
    
    YRX_RESULT result = yrx_compiler_add_source(nullptr, "rule test { condition: true }");
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null compiler returns INVALID_ARGUMENT");
}

void test_invalid_argument_null_rules() {
    std::cout << "\n=== Test: Invalid Argument - Null Rules ===" << std::endl;
    
    YRX_SCANNER* scanner = nullptr;
    YRX_RESULT result = yrx_scanner_create(nullptr, &scanner);
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null rules returns INVALID_ARGUMENT");
}

void test_invalid_argument_null_scanner() {
    std::cout << "\n=== Test: Invalid Argument - Null Scanner ===" << std::endl;
    
    const char* data = "test";
    YRX_RESULT result = yrx_scanner_scan(nullptr, reinterpret_cast<const uint8_t*>(data), strlen(data));
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null scanner returns INVALID_ARGUMENT");
}

void test_variable_error_undefined() {
    std::cout << "\n=== Test: Variable Error - Undefined ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    YRX_RESULT add_result = yrx_compiler_add_source(compiler, R"(
        rule use_var {
            condition:
                my_var > 0
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    
    TEST_ASSERT(rules == nullptr || add_result == YRX_SYNTAX_ERROR, "Build fails with undefined variable");
    
    const char* error = yrx_last_error();
    TEST_ASSERT(error != nullptr, "Error message is set");
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
    yrx_compiler_destroy(compiler);
}

void test_variable_error_wrong_type() {
    std::cout << "\n=== Test: Variable Error - Wrong Type ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    YRX_RESULT result = yrx_compiler_define_global_int(compiler, "my_int", 100);
    TEST_ASSERT(result == YRX_SUCCESS, "Define int variable");
    
    result = yrx_compiler_define_global_str(compiler, "my_int", "string");
    TEST_ASSERT(result == YRX_VARIABLE_ERROR, "Redefine with wrong type fails");
    
    yrx_compiler_destroy(compiler);
}

void test_compiler_errors_json() {
    std::cout << "\n=== Test: Compiler Errors JSON ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, R"(
        rule error_test {
            condition:
                undefined_identifier
        }
    )");
    
    YRX_BUFFER* buffer = nullptr;
    YRX_RESULT result = yrx_compiler_errors_json(compiler, &buffer);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Get errors as JSON");
    
    if (buffer && buffer->data) {
        std::string json(reinterpret_cast<char*>(buffer->data), buffer->length);
        std::cout << "    Errors JSON: " << json.substr(0, 200) << "..." << std::endl;
        
        TEST_ASSERT(json.find("undefined_identifier") != std::string::npos || 
                     json.find("UnknownIdentifier") != std::string::npos ||
                     json.find("undefined") != std::string::npos,
                     "JSON contains error info");
        
        yrx_buffer_destroy(buffer);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_compiler_warnings_json() {
    std::cout << "\n=== Test: Compiler Warnings JSON ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, R"(
        rule warning_test {
            strings:
                $a = "test"
            condition:
                true
        }
    )");
    
    YRX_BUFFER* buffer = nullptr;
    YRX_RESULT result = yrx_compiler_warnings_json(compiler, &buffer);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Get warnings as JSON");
    
    if (buffer && buffer->data) {
        std::string json(reinterpret_cast<char*>(buffer->data), buffer->length);
        std::cout << "    Warnings JSON length: " << json.length() << std::endl;
        yrx_buffer_destroy(buffer);
    }
    
    yrx_compiler_destroy(compiler);
}

void test_last_error_clears() {
    std::cout << "\n=== Test: Last Error Clears ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule invalid { condition: undefined }", &rules);
    
    const char* error1 = yrx_last_error();
    TEST_ASSERT(error1 != nullptr, "Error is set after failure");
    
    YRX_RULES* good_rules = nullptr;
    YRX_RESULT result = yrx_compile("rule valid { condition: true }", &good_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Valid compile succeeds");
    
    const char* error2 = yrx_last_error();
    TEST_ASSERT(error2 == nullptr, "Error cleared after success");
    
    if (good_rules) {
        yrx_rules_destroy(good_rules);
    }
}

void test_empty_source() {
    std::cout << "\n=== Test: Empty Source ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile("", &rules);
    
    TEST_ASSERT(result == YRX_SUCCESS || result == YRX_SYNTAX_ERROR, "Empty source handled");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 0, "No rules compiled from empty source");
        yrx_rules_destroy(rules);
    }
}

void test_scanner_timeout() {
    std::cout << "\n=== Test: Scanner Timeout ===" << std::endl;
    
    const char* rule = R"(
        rule timeout_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        result = yrx_scanner_set_timeout(scanner, 1);
        TEST_ASSERT(result == YRX_SUCCESS, "Set timeout to 1 second");
        
        const char* data = "test data";
        result = yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        TEST_ASSERT(result == YRX_SUCCESS, "Scan completes within timeout");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Error Handling Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_syntax_error();
    test_unknown_identifier();
    test_invalid_regex();
    test_invalid_hex_pattern();
    test_duplicate_rule_name();
    test_invalid_argument_null_compiler();
    test_invalid_argument_null_rules();
    test_invalid_argument_null_scanner();
    test_variable_error_undefined();
    test_variable_error_wrong_type();
    test_compiler_errors_json();
    test_compiler_warnings_json();
    test_last_error_clears();
    test_empty_source();
    test_scanner_timeout();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
