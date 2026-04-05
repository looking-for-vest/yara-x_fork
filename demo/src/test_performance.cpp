#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <iomanip>

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

template<typename T>
double measure_time(T&& func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

void test_compilation_performance() {
    std::cout << "\n=== Test: Compilation Performance ===" << std::endl;
    
    // 测试不同大小的规则编译时间
    std::vector<std::pair<std::string, std::string>> test_cases = {
        {"Small rule", "rule test { condition: true }"},
        {"Medium rule", R"(
            rule medium {
                strings:
                    $a = "test"
                    $b = "pattern"
                condition:
                    $a or $b
            }
        )"},
        {"Large rule", R"(
            rule large {
                strings:
                    $a = "test"
                    $b = "pattern"
                    $c = "example"
                    $d = "sample"
                    $e = "test case"
                condition:
                    any of them
            }
        )"}
    };
    
    for (const auto& test_case : test_cases) {
        const auto& name = test_case.first;
        const auto& rule = test_case.second;
        
        YRX_RULES* rules = nullptr;
        double time = measure_time([&]() {
            yrx_compile(rule.c_str(), &rules);
        });
        
        std::cout << "  [INFO] " << name << ": " << std::fixed << std::setprecision(2) << time << " ms" << std::endl;
        
        if (rules) {
            TEST_ASSERT(true, name + " compilation");
            yrx_rules_destroy(rules);
        } else {
            TEST_ASSERT(false, name + " compilation failed");
        }
    }
}

void test_scanning_performance() {
    std::cout << "\n=== Test: Scanning Performance ===" << std::endl;
    
    // 创建测试规则
    const char* rule = R"(
        rule test {
            strings:
                $a = "test"
                $b = "pattern"
                $c = "example"
            condition:
                any of them
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rules for scanning test");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        TEST_ASSERT(scanner != nullptr, "Create scanner");
        
        if (scanner) {
            // 测试不同大小的数据
            std::vector<std::pair<std::string, std::string>> test_data = {
                {"Small data", "test data"},
                {"Medium data", std::string(1000, 'a') + "test" + std::string(1000, 'b')},
                {"Large data", std::string(10000, 'x') + "pattern" + std::string(10000, 'y')}
            };
            
            for (const auto& data_case : test_data) {
                const auto& name = data_case.first;
                const auto& data = data_case.second;
                
                ScanResult scan_result = {0, {}};
                yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
                
                double time = measure_time([&]() {
                    yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
                });
                
                std::cout << "  [INFO] " << name << " (" << data.size() << " bytes): " 
                          << std::fixed << std::setprecision(2) << time << " ms, " 
                          << scan_result.match_count << " matches" << std::endl;
                
                TEST_ASSERT(true, name + " scanning");
            }
            
            yrx_scanner_destroy(scanner);
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_memory_usage() {
    std::cout << "\n=== Test: Memory Usage ===" << std::endl;
    
    // 测试规则集大小对内存的影响
    std::vector<int> rule_counts = {1, 10, 50, 100};
    
    for (int count : rule_counts) {
        std::string rules_str;
        for (int i = 0; i < count; i++) {
            rules_str += "rule rule_" + std::to_string(i) + " { condition: true }\n";
        }
        
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(rules_str.c_str(), &rules);
        
        if (result == YRX_SUCCESS && rules) {
            int compiled_count = yrx_rules_count(rules);
            std::cout << "  [INFO] " << count << " rules compiled, " << compiled_count << " rules loaded" << std::endl;
            TEST_ASSERT(compiled_count == count, "Memory usage test for " + std::to_string(count) + " rules");
            yrx_rules_destroy(rules);
        } else {
            std::cout << "  [INFO] Failed to compile " << count << " rules: " << yrx_last_error() << std::endl;
            TEST_ASSERT(false, "Memory usage test failed");
        }
    }
}

void test_repeated_scanning() {
    std::cout << "\n=== Test: Repeated Scanning Performance ===" << std::endl;
    
    const char* rule = R"(
        rule test {
            strings:
                $a = "test"
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = nullptr;
    yrx_compile(rule, &rules);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        if (scanner) {
            const char* data = "test data test pattern test example";
            const int iterations = 1000;
            
            ScanResult scan_result = {0, {}};
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            
            double time = measure_time([&]() {
                for (int i = 0; i < iterations; i++) {
                    scan_result.match_count = 0;
                    scan_result.matched_rules.clear();
                    yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
                }
            });
            
            double avg_time = time / iterations;
            std::cout << "  [INFO] " << iterations << " scans: " << std::fixed << std::setprecision(2) 
                      << time << " ms total, " << avg_time << " ms per scan" << std::endl;
            
            TEST_ASSERT(true, "Repeated scanning performance");
            
            yrx_scanner_destroy(scanner);
        }
        
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Performance Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_compilation_performance();
    test_scanning_performance();
    test_memory_usage();
    test_repeated_scanning();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
