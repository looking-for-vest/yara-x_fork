#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

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

struct MetadataInfo {
    std::string identifier;
    YRX_METADATA_TYPE type;
    std::string str_value;
    int64_t int_value;
    double float_value;
    bool bool_value;
};

void metadata_callback(const YRX_METADATA* metadata, void* user_data) {
    std::vector<MetadataInfo>* list = static_cast<std::vector<MetadataInfo>*>(user_data);
    
    MetadataInfo info;
    info.identifier = metadata->identifier;
    info.type = metadata->value_type;
    
    switch (metadata->value_type) {
        case YRX_I64:
            info.int_value = metadata->value.i64;
            break;
        case YRX_F64:
            info.float_value = metadata->value.f64;
            break;
        case YRX_BOOLEAN:
            info.bool_value = metadata->value.boolean;
            break;
        case YRX_STRING:
            info.str_value = metadata->value.string;
            break;
        case YRX_BYTES:
            info.str_value = std::string(
                reinterpret_cast<const char*>(metadata->value.bytes.data),
                metadata->value.bytes.length
            );
            break;
    }
    
    list->push_back(info);
}

void test_pattern_matching() {
    std::cout << "\n=== Test: Pattern Matching ===" << std::endl;
    
    // 测试字符串模式
    const char* string_rule = R"(
        rule string_test {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                $a and $b
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(string_rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile string pattern rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult scan_result = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        
        const char* data = "hello world";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(scan_result.match_count == 1, "String pattern matching");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
    
    // 测试十六进制模式
    const char* hex_rule = R"(
        rule hex_test {
            strings:
                $hex = { 48 65 6C 6C 6F }
            condition:
                $hex
        }
    )";
    
    result = yrx_compile(hex_rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile hex pattern rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult scan_result = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        
        const char* data = "Hello World";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(scan_result.match_count == 1, "Hex pattern matching");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
    
    // 测试正则表达式
    const char* regex_rule = R"(
        rule regex_test {
            strings:
                $re = /test\d+/
            condition:
                $re
        }
    )";
    
    result = yrx_compile(regex_rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile regex pattern rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        ScanResult scan_result = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
        
        const char* data = "test123";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        TEST_ASSERT(scan_result.match_count == 1, "Regex pattern matching");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_metadata_handling() {
    std::cout << "\n=== Test: Metadata Handling ===" << std::endl;
    
    const char* rule = R"(
        rule metadata_test {
            meta:
                author = "Test Author"
                version = 1
                enabled = true
                score = 95.5
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with metadata");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        std::vector<MetadataInfo> metadata_list;
        
        auto rule_with_metadata_callback = [](const YRX_RULE* rule, void* user_data) {
            std::vector<MetadataInfo>* list = static_cast<std::vector<MetadataInfo>*>(user_data);
            yrx_rule_iter_metadata(rule, metadata_callback, list);
        };
        
        yrx_scanner_on_matching_rule(scanner, rule_with_metadata_callback, &metadata_list);
        yrx_scanner_scan(scanner, nullptr, 0);
        
        TEST_ASSERT(metadata_list.size() == 4, "Metadata count");
        
        bool found_author = false;
        bool found_version = false;
        bool found_enabled = false;
        bool found_score = false;
        
        for (const auto& meta : metadata_list) {
            if (meta.identifier == "author") {
                found_author = true;
                TEST_ASSERT(meta.type == YRX_STRING, "Author is string");
                TEST_ASSERT(meta.str_value == "Test Author", "Author value");
            } else if (meta.identifier == "version") {
                found_version = true;
                TEST_ASSERT(meta.type == YRX_I64, "Version is integer");
                TEST_ASSERT(meta.int_value == 1, "Version value");
            } else if (meta.identifier == "enabled") {
                found_enabled = true;
                TEST_ASSERT(meta.type == YRX_BOOLEAN, "Enabled is boolean");
                TEST_ASSERT(meta.bool_value == true, "Enabled value");
            } else if (meta.identifier == "score") {
                found_score = true;
                TEST_ASSERT(meta.type == YRX_F64, "Score is float");
                TEST_ASSERT(meta.float_value > 95.0 && meta.float_value < 96.0, "Score value");
            }
        }
        
        TEST_ASSERT(found_author && found_version && found_enabled && found_score, "All metadata found");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

void test_global_variables() {
    std::cout << "\n=== Test: Global Variables ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (compiler) {
        // 定义全局变量
        result = yrx_compiler_define_global_str(compiler, "target", "test");
        TEST_ASSERT(result == YRX_SUCCESS, "Define global string");
        
        result = yrx_compiler_define_global_int(compiler, "threshold", 100);
        TEST_ASSERT(result == YRX_SUCCESS, "Define global integer");
        
        // 使用全局变量
        const char* rule = R"(
            rule global_test {
                strings:
                    $a = "test"
                condition:
                    $a and threshold > 50
            }
        )";
        
        result = yrx_compiler_add_source(compiler, rule);
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global variables");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules with globals");
        
        if (rules) {
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            
            ScanResult scan_result = {0, {}};
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            
            const char* data = "test data";
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            
            TEST_ASSERT(scan_result.match_count == 1, "Global variables in condition");
            
            // 测试扫描器级别的全局变量修改
            result = yrx_scanner_set_global_int(scanner, "threshold", 200);
            TEST_ASSERT(result == YRX_SUCCESS, "Set global int at scanner level");
            
            scan_result.match_count = 0;
            scan_result.matched_rules.clear();
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            
            TEST_ASSERT(scan_result.match_count == 1, "Global variable modification");
            
            yrx_scanner_destroy(scanner);
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

// 标签回调函数
void tag_callback(const char* tag, void* user_data) {
    std::vector<std::string>* tag_list = static_cast<std::vector<std::string>*>(user_data);
    tag_list->push_back(tag);
}

// 规则回调函数，带有标签处理
void rule_with_tags_callback(const YRX_RULE* rule, void* user_data) {
    std::vector<std::string>* tag_list = static_cast<std::vector<std::string>*>(user_data);
    yrx_rule_iter_tags(rule, tag_callback, tag_list);
}

void test_rule_tags() {
    std::cout << "\n=== Test: Rule Tags ===" << std::endl;
    
    const char* rule = R"(
        rule tagged_rule : malware trojan windows {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with tags");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        std::vector<std::string> tags;
        
        yrx_scanner_on_matching_rule(scanner, rule_with_tags_callback, &tags);
        yrx_scanner_scan(scanner, nullptr, 0);
        
        TEST_ASSERT(tags.size() == 3, "Tag count");
        
        bool found_malware = false;
        bool found_trojan = false;
        bool found_windows = false;
        
        for (const auto& tag : tags) {
            if (tag == "malware") found_malware = true;
            if (tag == "trojan") found_trojan = true;
            if (tag == "windows") found_windows = true;
        }
        
        TEST_ASSERT(found_malware && found_trojan && found_windows, "All tags found");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

// 命名空间回调函数
void namespace_callback(const YRX_RULE* rule, void* user_data) {
    std::string* ns = static_cast<std::string*>(user_data);
    const uint8_t* ns_ptr = nullptr;
    size_t len = 0;
    if (yrx_rule_namespace(rule, &ns_ptr, &len) == YRX_SUCCESS) {
        *ns = std::string(reinterpret_cast<const char*>(ns_ptr), len);
    }
}

void test_namespaces() {
    std::cout << "\n=== Test: Namespaces ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (compiler) {
        // 切换到自定义命名空间
        result = yrx_compiler_new_namespace(compiler, "test_namespace");
        TEST_ASSERT(result == YRX_SUCCESS, "Create namespace");
        
        const char* rule = R"(
            rule namespaced_rule {
                condition:
                    true
            }
        )";
        
        result = yrx_compiler_add_source(compiler, rule);
        TEST_ASSERT(result == YRX_SUCCESS, "Add rule to namespace");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules with namespace");
        
        if (rules) {
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            
            std::string rule_namespace;
            
            yrx_scanner_on_matching_rule(scanner, namespace_callback, &rule_namespace);
            yrx_scanner_scan(scanner, nullptr, 0);
            
            TEST_ASSERT(rule_namespace == "test_namespace", "Namespace correct");
            
            yrx_scanner_destroy(scanner);
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Functionality Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_pattern_matching();
    test_metadata_handling();
    test_global_variables();
    test_rule_tags();
    test_namespaces();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
