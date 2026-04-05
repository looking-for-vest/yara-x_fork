#include <iostream>
#include <cassert>
#include <cstring>
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

struct ScanResult {
    int match_count;
    std::vector<std::string> matched_rules;
};

void rule_callback(const YRX_RULE* rule, void* user_data) {
    ScanResult* result = static_cast<ScanResult*>(user_data);
    result->match_count++;
    
    const uint8_t* ident = nullptr;
    size_t len = 0;
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        std::string name(reinterpret_cast<const char*>(ident), len);
        result->matched_rules.push_back(name);
    }
}

void test_global_bool() {
    std::cout << "\n=== Test: Global Boolean Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (result == YRX_SUCCESS) {
        result = yrx_compiler_define_global_bool(compiler, "my_bool", true);
        TEST_ASSERT(result == YRX_SUCCESS, "Define global bool");
        
        result = yrx_compiler_add_source(compiler, R"(
            rule bool_test {
                condition:
                    my_bool
            }
        )");
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global bool");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules");
        
        if (rules) {
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
            yrx_scanner_destroy(scanner);
            
            TEST_ASSERT(scan_result.match_count == 1, "Match with bool=true");
            
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

void test_global_int() {
    std::cout << "\n=== Test: Global Integer Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (result == YRX_SUCCESS) {
        result = yrx_compiler_define_global_int(compiler, "my_int", 100);
        TEST_ASSERT(result == YRX_SUCCESS, "Define global int");
        
        result = yrx_compiler_add_source(compiler, R"(
            rule int_test {
                condition:
                    my_int > 50
            }
        )");
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global int");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules");
        
        if (rules) {
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
            yrx_scanner_destroy(scanner);
            
            TEST_ASSERT(scan_result.match_count == 1, "Match with int > 50");
            
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

void test_global_float() {
    std::cout << "\n=== Test: Global Float Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (result == YRX_SUCCESS) {
        result = yrx_compiler_define_global_float(compiler, "my_float", 3.14159);
        TEST_ASSERT(result == YRX_SUCCESS, "Define global float");
        
        result = yrx_compiler_add_source(compiler, R"(
            rule float_test {
                condition:
                    my_float > 3.0 and my_float < 4.0
            }
        )");
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global float");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules");
        
        if (rules) {
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
            yrx_scanner_destroy(scanner);
            
            TEST_ASSERT(scan_result.match_count == 1, "Match with float in range");
            
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

void test_global_string() {
    std::cout << "\n=== Test: Global String Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (result == YRX_SUCCESS) {
        result = yrx_compiler_define_global_str(compiler, "my_str", "expected_value");
        TEST_ASSERT(result == YRX_SUCCESS, "Define global string");
        
        result = yrx_compiler_add_source(compiler, R"(
            rule string_test {
                condition:
                    my_str == "expected_value"
            }
        )");
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global string");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules");
        
        if (rules) {
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
            yrx_scanner_destroy(scanner);
            
            TEST_ASSERT(scan_result.match_count == 1, "Match with correct string");
            
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

void test_scanner_set_global_bool() {
    std::cout << "\n=== Test: Scanner Set Global Bool ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_bool(compiler, "my_flag", false);
    yrx_compiler_add_source(compiler, R"(
        rule flag_test {
            condition:
                my_flag
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult result1 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result1);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result1.match_count == 0, "No match with default false");
        
        YRX_RESULT set_result = yrx_scanner_set_global_bool(scanner, "my_flag", true);
        TEST_ASSERT(set_result == YRX_SUCCESS, "Set global bool to true");
        
        ScanResult result2 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result2);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result2.match_count == 1, "Match after setting to true");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_scanner_set_global_int() {
    std::cout << "\n=== Test: Scanner Set Global Int ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_int(compiler, "threshold", 100);
    yrx_compiler_add_source(compiler, R"(
        rule threshold_test {
            condition:
                threshold > 150
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult result1 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result1);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result1.match_count == 0, "No match with threshold=100");
        
        YRX_RESULT set_result = yrx_scanner_set_global_int(scanner, "threshold", 200);
        TEST_ASSERT(set_result == YRX_SUCCESS, "Set global int to 200");
        
        ScanResult result2 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result2);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result2.match_count == 1, "Match with threshold=200");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_scanner_set_global_string() {
    std::cout << "\n=== Test: Scanner Set Global String ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_str(compiler, "mode", "default");
    yrx_compiler_add_source(compiler, R"(
        rule mode_test {
            condition:
                mode == "special"
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult result1 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result1);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result1.match_count == 0, "No match with mode='default'");
        
        YRX_RESULT set_result = yrx_scanner_set_global_str(scanner, "mode", "special");
        TEST_ASSERT(set_result == YRX_SUCCESS, "Set global string to 'special'");
        
        ScanResult result2 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result2);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result2.match_count == 1, "Match with mode='special'");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_scanner_set_global_float() {
    std::cout << "\n=== Test: Scanner Set Global Float ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_float(compiler, "ratio", 1.0);
    yrx_compiler_add_source(compiler, R"(
        rule ratio_test {
            condition:
                ratio >= 2.5
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult result1 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result1);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result1.match_count == 0, "No match with ratio=1.0");
        
        YRX_RESULT set_result = yrx_scanner_set_global_float(scanner, "ratio", 3.0);
        TEST_ASSERT(set_result == YRX_SUCCESS, "Set global float to 3.0");
        
        ScanResult result2 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result2);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result2.match_count == 1, "Match with ratio=3.0");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_multiple_global_vars() {
    std::cout << "\n=== Test: Multiple Global Variables ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_bool(compiler, "enabled", true);
    yrx_compiler_define_global_int(compiler, "count", 10);
    yrx_compiler_define_global_str(compiler, "name", "test");
    
    yrx_compiler_add_source(compiler, R"(
        rule multi_global {
            condition:
                enabled and count > 5 and name == "test"
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules with multiple globals");
    
    if (rules) {
        ScanResult scan_result = {0, {}};
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(scan_result.match_count == 1, "Match with all conditions met");
        
        yrx_rules_destroy(rules);
    }
}

void test_global_json() {
    std::cout << "\n=== Test: Global JSON Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* json_value = R"({"key": "value", "number": 42})";
    YRX_RESULT result = yrx_compiler_define_global_json(compiler, "my_json", json_value);
    TEST_ASSERT(result == YRX_SUCCESS, "Define global JSON");
    
    yrx_compiler_add_source(compiler, R"(
        rule json_test {
            condition:
                true
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Build rules with JSON global");
    
    if (rules) {
        ScanResult scan_result = {0, {}};
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(scan_result.match_count == 1, "Match with JSON global defined");
        
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Global Variables Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_global_bool();
    test_global_int();
    test_global_float();
    test_global_string();
    test_scanner_set_global_bool();
    test_scanner_set_global_int();
    test_scanner_set_global_string();
    test_scanner_set_global_float();
    test_multiple_global_vars();
    test_global_json();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
