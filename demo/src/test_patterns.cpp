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
    std::vector<std::pair<size_t, size_t>> match_offsets;
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

void pattern_callback(const YRX_PATTERN* pattern, void* user_data) {
    auto match_callback = [](const YRX_MATCH* match, void* user_data) {
        ScanResult* result = static_cast<ScanResult*>(user_data);
        result->match_offsets.push_back({match->offset, match->length});
    };
    
    yrx_pattern_iter_matches(pattern, match_callback, user_data);
}

YRX_RULES* compile_rule(const char* rule) {
    YRX_RULES* rules = nullptr;
    yrx_compile(rule, &rules);
    return rules;
}

ScanResult scan_data(YRX_RULES* rules, const uint8_t* data, size_t len) {
    ScanResult result = {0, {}, {}};
    
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    
    yrx_scanner_on_matching_rule(scanner, rule_callback, &result);
    yrx_scanner_scan(scanner, data, len);
    
    yrx_scanner_destroy(scanner);
    
    return result;
}

void test_string_pattern() {
    std::cout << "\n=== Test: String Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule string_test {
            strings:
                $a = "hello"
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile string pattern rule");
    
    if (rules) {
        const char* data = "hello world";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for 'hello'");
        if (result.match_count == 1) {
            TEST_ASSERT(result.matched_rules[0] == "string_test", "Rule name is correct");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_nocase_pattern() {
    std::cout << "\n=== Test: NoCase Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule nocase_test {
            strings:
                $a = "HELLO" nocase
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile nocase pattern rule");
    
    if (rules) {
        const char* data = "hello world";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found with nocase");
        
        yrx_rules_destroy(rules);
    }
}

void test_wide_pattern() {
    std::cout << "\n=== Test: Wide Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule wide_test {
            strings:
                $a = "hello" wide
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile wide pattern rule");
    
    if (rules) {
        const uint8_t wide_data[] = {'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0};
        ScanResult result = scan_data(rules, wide_data, sizeof(wide_data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for wide string");
        
        yrx_rules_destroy(rules);
    }
}

void test_fullword_pattern() {
    std::cout << "\n=== Test: FullWord Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule fullword_test {
            strings:
                $a = "test" fullword
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile fullword pattern rule");
    
    if (rules) {
        const char* data1 = "this is a test string";
        ScanResult result1 = scan_data(rules, reinterpret_cast<const uint8_t*>(data1), strlen(data1));
        TEST_ASSERT(result1.match_count == 1, "Match found for fullword 'test'");
        
        const char* data2 = "this is testing";
        ScanResult result2 = scan_data(rules, reinterpret_cast<const uint8_t*>(data2), strlen(data2));
        TEST_ASSERT(result2.match_count == 0, "No match for non-fullword 'testing'");
        
        yrx_rules_destroy(rules);
    }
}

void test_hex_pattern() {
    std::cout << "\n=== Test: Hex Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule hex_test {
            strings:
                $hex = { 48 65 6C 6C 6F }
            condition:
                $hex
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile hex pattern rule");
    
    if (rules) {
        const char* data = "Hello World";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for hex pattern");
        
        yrx_rules_destroy(rules);
    }
}

void test_hex_with_jumps() {
    std::cout << "\n=== Test: Hex With Jumps ===" << std::endl;
    
    const char* rule = R"(
        rule hex_jump_test {
            strings:
                $hex = { 48 [2-5] 6F }
            condition:
                $hex
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile hex jump pattern rule");
    
    if (rules) {
        const char* data = "Hello World";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for hex with jumps");
        
        yrx_rules_destroy(rules);
    }
}

void test_hex_wildcard() {
    std::cout << "\n=== Test: Hex Wildcard ===" << std::endl;
    
    const char* rule = R"(
        rule hex_wildcard_test {
            strings:
                $hex = { 48 ?? 6C 6F }
            condition:
                $hex
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile hex wildcard pattern rule");
    
    if (rules) {
        const char* data = "Halo World";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for hex wildcard");
        
        yrx_rules_destroy(rules);
    }
}

void test_regex_pattern() {
    std::cout << "\n=== Test: Regex Pattern ===" << std::endl;
    
    const char* rule = R"(
        rule regex_test {
            strings:
                $re = /test.*pattern/
            condition:
                $re
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile regex pattern rule");
    
    if (rules) {
        const char* data = "this is a test_pattern example";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for regex");
        
        yrx_rules_destroy(rules);
    }
}

void test_regex_case_insensitive() {
    std::cout << "\n=== Test: Regex Case Insensitive ===" << std::endl;
    
    const char* rule = R"(
        rule regex_nocase_test {
            strings:
                $re = /HELLO/i
            condition:
                $re
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile case insensitive regex rule");
    
    if (rules) {
        const char* data = "hello world";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match found for case insensitive regex");
        
        yrx_rules_destroy(rules);
    }
}

void test_multiple_patterns() {
    std::cout << "\n=== Test: Multiple Patterns ===" << std::endl;
    
    const char* rule = R"(
        rule multi_pattern {
            strings:
                $a = "foo"
                $b = "bar"
                $c = "baz"
            condition:
                any of them
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile multiple pattern rule");
    
    if (rules) {
        const char* data1 = "foo is here";
        ScanResult result1 = scan_data(rules, reinterpret_cast<const uint8_t*>(data1), strlen(data1));
        TEST_ASSERT(result1.match_count == 1, "Match found for 'foo'");
        
        const char* data2 = "bar is here";
        ScanResult result2 = scan_data(rules, reinterpret_cast<const uint8_t*>(data2), strlen(data2));
        TEST_ASSERT(result2.match_count == 1, "Match found for 'bar'");
        
        const char* data3 = "nothing here";
        ScanResult result3 = scan_data(rules, reinterpret_cast<const uint8_t*>(data3), strlen(data3));
        TEST_ASSERT(result3.match_count == 0, "No match for 'nothing'");
        
        yrx_rules_destroy(rules);
    }
}

void test_all_of() {
    std::cout << "\n=== Test: All Of Condition ===" << std::endl;
    
    const char* rule = R"(
        rule all_of_test {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                all of them
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile all of rule");
    
    if (rules) {
        const char* data1 = "hello world";
        ScanResult result1 = scan_data(rules, reinterpret_cast<const uint8_t*>(data1), strlen(data1));
        TEST_ASSERT(result1.match_count == 1, "Match when all patterns present");
        
        const char* data2 = "hello only";
        ScanResult result2 = scan_data(rules, reinterpret_cast<const uint8_t*>(data2), strlen(data2));
        TEST_ASSERT(result2.match_count == 0, "No match when not all patterns present");
        
        yrx_rules_destroy(rules);
    }
}

void test_count_operator() {
    std::cout << "\n=== Test: Count Operator ===" << std::endl;
    
    const char* rule = R"(
        rule count_test {
            strings:
                $a = "test"
            condition:
                #a > 1
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile count operator rule");
    
    if (rules) {
        const char* data = "test test test";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match when count > 1");
        
        yrx_rules_destroy(rules);
    }
}

void test_offset_operator() {
    std::cout << "\n=== Test: Offset Operator ===" << std::endl;
    
    const char* rule = R"(
        rule offset_test {
            strings:
                $a = "test"
            condition:
                @a == 0
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile offset operator rule");
    
    if (rules) {
        const char* data = "test at start";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match at offset 0");
        
        yrx_rules_destroy(rules);
    }
}

void test_filesize_condition() {
    std::cout << "\n=== Test: Filesize Condition ===" << std::endl;
    
    const char* rule = R"(
        rule filesize_test {
            condition:
                filesize > 5
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile filesize condition rule");
    
    if (rules) {
        const char* data = "hello world";
        ScanResult result = scan_data(rules, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(result.match_count == 1, "Match for filesize > 5");
        
        const char* small_data = "hi";
        ScanResult result2 = scan_data(rules, reinterpret_cast<const uint8_t*>(small_data), strlen(small_data));
        
        TEST_ASSERT(result2.match_count == 0, "No match for filesize <= 5");
        
        yrx_rules_destroy(rules);
    }
}

void test_match_offset_length() {
    std::cout << "\n=== Test: Match Offset and Length ===" << std::endl;
    
    const char* rule = R"(
        rule offset_length_test {
            strings:
                $a = "hello"
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile offset/length test rule");
    
    if (rules) {
        const char* data = "say hello world";
        
        ScanResult scan_result = {0, {}, {}};
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(scan_result.match_count == 1, "Match found");
        
        if (!scan_result.match_offsets.empty()) {
            TEST_ASSERT(scan_result.match_offsets[0].first == 4, "Match offset is 4");
            TEST_ASSERT(scan_result.match_offsets[0].second == 5, "Match length is 5");
        }
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Pattern Matching Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_string_pattern();
    test_nocase_pattern();
    test_wide_pattern();
    test_fullword_pattern();
    test_hex_pattern();
    test_hex_with_jumps();
    test_hex_wildcard();
    test_regex_pattern();
    test_regex_case_insensitive();
    test_multiple_patterns();
    test_all_of();
    test_count_operator();
    test_offset_operator();
    test_filesize_condition();
    test_match_offset_length();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
