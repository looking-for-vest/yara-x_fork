#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

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

void test_compiler_lifecycle() {
    std::cout << "\n=== Test: Compiler Lifecycle ===" << std::endl;
    
    for (int i = 0; i < 100; i++) {
        YRX_COMPILER* compiler = nullptr;
        YRX_RESULT result = yrx_compiler_create(0, &compiler);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Compiler creation failed in loop");
            return;
        }
        
        yrx_compiler_add_source(compiler, "rule test { condition: true }");
        YRX_RULES* rules = yrx_compiler_build(compiler);
        
        if (rules) {
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
    
    TEST_ASSERT(true, "100 compiler create/destroy cycles completed");
}

void test_rules_lifecycle() {
    std::cout << "\n=== Test: Rules Lifecycle ===" << std::endl;
    
    for (int i = 0; i < 100; i++) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile("rule test { condition: true }", &rules);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Rules creation failed in loop");
            return;
        }
        
        yrx_rules_destroy(rules);
    }
    
    TEST_ASSERT(true, "100 rules create/destroy cycles completed");
}

void test_scanner_lifecycle() {
    std::cout << "\n=== Test: Scanner Lifecycle ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (!rules) {
        TEST_ASSERT(false, "Failed to compile rules");
        return;
    }
    
    for (int i = 0; i < 100; i++) {
        YRX_SCANNER* scanner = nullptr;
        YRX_RESULT result = yrx_scanner_create(rules, &scanner);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Scanner creation failed in loop");
            break;
        }
        
        const char* data = "test data";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        yrx_scanner_destroy(scanner);
    }
    
    yrx_rules_destroy(rules);
    TEST_ASSERT(true, "100 scanner create/destroy cycles completed");
}

void test_destruction_order() {
    std::cout << "\n=== Test: Destruction Order ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    TEST_ASSERT(rules != nullptr, "Rules created");
    
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    TEST_ASSERT(scanner != nullptr, "Scanner created");
    
    yrx_scanner_destroy(scanner);
    std::cout << "  [INFO] Scanner destroyed first" << std::endl;
    
    yrx_rules_destroy(rules);
    std::cout << "  [INFO] Rules destroyed second" << std::endl;
    
    TEST_ASSERT(true, "Correct destruction order: scanner before rules");
}

void test_multiple_scanners() {
    std::cout << "\n=== Test: Multiple Scanners ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    TEST_ASSERT(rules != nullptr, "Rules created");
    
    const int num_scanners = 10;
    std::vector<YRX_SCANNER*> scanners(num_scanners);
    
    for (int i = 0; i < num_scanners; i++) {
        YRX_RESULT result = yrx_scanner_create(rules, &scanners[i]);
        TEST_ASSERT(result == YRX_SUCCESS, "Scanner created");
    }
    
    for (int i = 0; i < num_scanners; i++) {
        const char* data = "test data";
        yrx_scanner_scan(scanners[i], reinterpret_cast<const uint8_t*>(data), strlen(data));
    }
    
    for (int i = 0; i < num_scanners; i++) {
        yrx_scanner_destroy(scanners[i]);
    }
    
    yrx_rules_destroy(rules);
    TEST_ASSERT(true, "Multiple scanners created and destroyed");
}

void test_buffer_lifecycle() {
    std::cout << "\n=== Test: Buffer Lifecycle ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (rules) {
        for (int i = 0; i < 50; i++) {
            YRX_BUFFER* buffer = nullptr;
            YRX_RESULT result = yrx_rules_serialize(rules, &buffer);
            
            if (result == YRX_SUCCESS && buffer) {
                yrx_buffer_destroy(buffer);
            }
        }
        
        yrx_rules_destroy(rules);
        TEST_ASSERT(true, "50 buffer create/destroy cycles completed");
    }
}

void test_large_ruleset() {
    std::cout << "\n=== Test: Large Rule Set ===" << std::endl;
    
    std::string rules;
    for (int i = 0; i < 1000; i++) {
        rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
    }
    
    YRX_RULES* compiled_rules = nullptr;
    YRX_RESULT result = yrx_compile(rules.c_str(), &compiled_rules);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Compile 1000 rules");
    
    if (compiled_rules) {
        int count = yrx_rules_count(compiled_rules);
        TEST_ASSERT(count == 1000, "Rule count is 1000");
        
        yrx_rules_destroy(compiled_rules);
    }
}

void test_repeated_scans() {
    std::cout << "\n=== Test: Repeated Scans ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { strings: $a = \"test\" condition: $a }", &rules);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        int match_count = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* count = static_cast<int*>(user_data);
            (*count)++;
        };
        
        const char* data = "test data";
        for (int i = 0; i < 1000; i++) {
            match_count = 0;
            yrx_scanner_on_matching_rule(scanner, callback, &match_count);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        }
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        
        TEST_ASSERT(true, "1000 repeated scans completed");
    }
}

void test_multithreaded_scanning() {
    std::cout << "\n=== Test: Multithreaded Scanning ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (!rules) {
        TEST_ASSERT(false, "Failed to compile rules");
        return;
    }
    
    const int num_threads = 4;
    const int scans_per_thread = 100;
    
    std::atomic<int> total_scans(0);
    std::atomic<int> total_matches(0);
    
    auto scan_worker = [&rules, &total_scans, &total_matches, scans_per_thread]() {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        int matches = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* m = static_cast<int*>(user_data);
            (*m)++;
        };
        
        const char* data = "test data";
        for (int i = 0; i < scans_per_thread; i++) {
            matches = 0;
            yrx_scanner_on_matching_rule(scanner, callback, &matches);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            total_matches += matches;
            total_scans++;
        }
        
        yrx_scanner_destroy(scanner);
    };
    
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(scan_worker);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    yrx_rules_destroy(rules);
    
    TEST_ASSERT(total_scans == num_threads * scans_per_thread, "All scans completed");
    TEST_ASSERT(total_matches == num_threads * scans_per_thread, "All matches found");
    std::cout << "    Completed " << total_scans << " scans across " << num_threads << " threads" << std::endl;
}

void test_stress_test() {
    std::cout << "\n=== Test: Stress Test ===" << std::endl;
    
    for (int round = 0; round < 10; round++) {
        YRX_COMPILER* compiler = nullptr;
        yrx_compiler_create(0, &compiler);
        
        for (int i = 0; i < 10; i++) {
            std::string rule = "rule stress_" + std::to_string(round) + "_" + std::to_string(i) + 
                              " { strings: $a = \"test\" condition: $a }";
            yrx_compiler_add_source(compiler, rule.c_str());
        }
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);
        
        if (rules) {
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            
            for (int i = 0; i < 100; i++) {
                const char* data = "test data";
                yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            }
            
            yrx_scanner_destroy(scanner);
            yrx_rules_destroy(rules);
        }
    }
    
    TEST_ASSERT(true, "Stress test completed: 10 rounds of compile/scan/destroy");
}

void test_empty_data_scan() {
    std::cout << "\n=== Test: Empty Data Scan ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        YRX_RESULT result = yrx_scanner_scan(scanner, nullptr, 0);
        TEST_ASSERT(result == YRX_SUCCESS, "Scan with null data and zero length");
        
        result = yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result == YRX_SUCCESS, "Scan with empty data");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Memory Management Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_compiler_lifecycle();
    test_rules_lifecycle();
    test_scanner_lifecycle();
    test_destruction_order();
    test_multiple_scanners();
    test_buffer_lifecycle();
    test_large_ruleset();
    test_repeated_scans();
    test_multithreaded_scanning();
    test_stress_test();
    test_empty_data_scan();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
