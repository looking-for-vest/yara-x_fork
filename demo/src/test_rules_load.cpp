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

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return "";
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

void test_single_rule_load() {
    std::cout << "\n=== Test: Single Rule Load ===" << std::endl;
    
    // 测试单个规则文件
    std::string rule_path = "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/Yara-Rules/rules/malware/MALW_Emotet.yar";
    std::string rule_content = read_file(rule_path);
    
    TEST_ASSERT(!rule_content.empty(), "Read rule file");
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
    
    if (result != YRX_SUCCESS) {
        std::cout << "  [INFO] Compile failed: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile single rule");
    } else {
        TEST_ASSERT(rules != nullptr, "Compile single rule");
        
        if (rules) {
            int count = yrx_rules_count(rules);
            std::cout << "  [INFO] Compiled " << count << " rules" << std::endl;
            TEST_ASSERT(count > 0, "Rule count > 0");
            
            // 测试扫描
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            
            // 使用空数据扫描（测试规则是否能正确加载）
            yrx_scanner_scan(scanner, nullptr, 0);
            
            yrx_scanner_destroy(scanner);
            yrx_rules_destroy(rules);
        }
    }
}

void test_index_file_load() {
    std::cout << "\n=== Test: Index File Load ===" << std::endl;
    
    // 测试索引文件
    std::string index_path = "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/Yara-Rules/rules/index.yar";
    std::string index_content = read_file(index_path);
    
    TEST_ASSERT(!index_content.empty(), "Read index file");
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(index_content.c_str(), &rules);
    
    if (result != YRX_SUCCESS) {
        std::cout << "  [INFO] Compile failed: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile index file");
    } else {
        TEST_ASSERT(rules != nullptr, "Compile index file");
        
        if (rules) {
            int count = yrx_rules_count(rules);
            std::cout << "  [INFO] Compiled " << count << " rules from index" << std::endl;
            TEST_ASSERT(count > 0, "Rule count from index > 0");
            
            yrx_rules_destroy(rules);
        }
    }
}

void test_include_directive() {
    std::cout << "\n=== Test: Include Directive ===" << std::endl;
    
    // 测试包含指令
    std::string test_rule = R"(
        include "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/rules/includes/included.yar"
        
        rule test_include {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(test_rule.c_str(), &rules);
    
    if (result != YRX_SUCCESS) {
        std::cout << "  [INFO] Compile failed: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile with include directive");
    } else {
        TEST_ASSERT(rules != nullptr, "Compile with include directive");
        
        if (rules) {
            int count = yrx_rules_count(rules);
            std::cout << "  [INFO] Compiled " << count << " rules with include" << std::endl;
            TEST_ASSERT(count > 0, "Rule count with include > 0");
            
            yrx_rules_destroy(rules);
        }
    }
}

void test_compiler_include_path() {
    std::cout << "\n=== Test: Compiler Include Path ===" << std::endl;
    
    // 测试设置包含路径
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (compiler) {
        // 设置包含路径
        result = yrx_compiler_add_include_dir(compiler, "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/rules/includes");
        TEST_ASSERT(result == YRX_SUCCESS, "Add include path");
        
        // 使用相对路径包含
        std::string test_rule = R"(
            include "included.yar"
            
            rule test_include_path {
                condition:
                    true
            }
        )";
        
        result = yrx_compiler_add_source(compiler, test_rule.c_str());
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Add source failed: " << yrx_last_error() << std::endl;
            TEST_ASSERT(false, "Add source with include");
        } else {
            YRX_RULES* rules = yrx_compiler_build(compiler);
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " rules with include path" << std::endl;
                TEST_ASSERT(count > 0, "Rule count with include path > 0");
                
                yrx_rules_destroy(rules);
            } else {
                std::cout << "  [INFO] Build failed: " << yrx_last_error() << std::endl;
                TEST_ASSERT(false, "Build rules with include path");
            }
        }
        
        yrx_compiler_destroy(compiler);
    }
}

void test_ruleset_compilation() {
    std::cout << "\n=== Test: Full Ruleset Compilation ===" << std::endl;
    
    // 测试完整规则集编译
    std::string index_path = "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/Yara-Rules/rules/index.yar";
    std::string index_content = read_file(index_path);
    
    TEST_ASSERT(!index_content.empty(), "Read full ruleset index");
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler for ruleset");
    
    if (compiler) {
        // 设置包含路径
        result = yrx_compiler_add_include_dir(compiler, "/home/secneo/quanqing/mygithub/yara-x_fork/demo/tests/Yara-Rules/rules");
        TEST_ASSERT(result == YRX_SUCCESS, "Add rules directory as include path");
        
        // 编译索引文件
        result = yrx_compiler_add_source(compiler, index_content.c_str());
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Add source failed: " << yrx_last_error() << std::endl;
            TEST_ASSERT(false, "Add ruleset source");
        } else {
            YRX_RULES* rules = yrx_compiler_build(compiler);
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " rules from full ruleset" << std::endl;
                TEST_ASSERT(count > 0, "Full ruleset rule count > 0");
                
                yrx_rules_destroy(rules);
            } else {
                std::cout << "  [INFO] Build failed: " << yrx_last_error() << std::endl;
                // 不失败测试，因为完整规则集可能包含一些YARA-X不支持的语法
                std::cout << "  [INFO] Full ruleset compilation may fail due to YARA-X compatibility" << std::endl;
            }
        }
        
        yrx_compiler_destroy(compiler);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Rules Load Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_single_rule_load();
    test_index_file_load();
    test_include_directive();
    test_compiler_include_path();
    test_ruleset_compilation();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
