#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <cstring>
#include <chrono>
#include <atomic>

extern "C" {
#include "yara_x.h"
}

std::mutex cout_mutex;
std::atomic<int> total_matches(0);

void rule_callback(const YRX_RULE* rule, void* user_data) {
    const uint8_t* ident = nullptr;
    size_t len = 0;
    
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        std::string rule_name(reinterpret_cast<const char*>(ident), len);
        
        const uint8_t* ns = nullptr;
        size_t ns_len = 0;
        
        if (yrx_rule_namespace(rule, &ns, &ns_len) == YRX_SUCCESS) {
            std::string namespace_str(reinterpret_cast<const char*>(ns), ns_len);
            
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "[Thread " << std::this_thread::get_id() << "] "
                      << "Matched rule: " << namespace_str << ":" << rule_name << std::endl;
        }
    }
    
    int* matches = static_cast<int*>(user_data);
    (*matches)++;
}

void pattern_callback(const YRX_PATTERN* pattern, void* user_data) {
    const uint8_t* ident = nullptr;
    size_t len = 0;
    
    if (yrx_pattern_identifier(pattern, &ident, &len) == YRX_SUCCESS) {
        std::string pattern_name(reinterpret_cast<const char*>(ident), len);
        
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  Pattern: " << pattern_name << std::endl;
    }
    
    auto match_callback = [](const YRX_MATCH* match, void* user_data) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "    Match at offset " << match->offset 
                  << ", length " << match->length << std::endl;
    };
    
    yrx_pattern_iter_matches(pattern, match_callback, user_data);
}

void scan_data(YRX_SCANNER* scanner, const std::string& data_name, 
               const std::vector<uint8_t>& data, int thread_id) {
    int matches = 0;
    
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scanning " << data_name << " (" << data.size() << " bytes)" 
                  << std::endl;
    }
    
    YRX_RESULT result = yrx_scanner_scan(scanner, data.data(), data.size());
    
    if (result == YRX_SUCCESS) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scan completed successfully. Matches: " << matches << std::endl;
        total_matches += matches;
    } else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scan failed: " << yrx_last_error() << std::endl;
    }
}

void scan_with_callback(YRX_SCANNER* scanner, const std::string& data_name,
                        const std::vector<uint8_t>& data, int thread_id) {
    int matches = 0;
    
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scanning " << data_name << " with callback (" << data.size() << " bytes)" 
                  << std::endl;
    }
    
    yrx_scanner_on_matching_rule(scanner, rule_callback, &matches);
    
    YRX_RESULT result = yrx_scanner_scan(scanner, data.data(), data.size());
    
    if (result == YRX_SUCCESS) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scan completed successfully. Matches: " << matches << std::endl;
        total_matches += matches;
    } else {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[Thread " << std::this_thread::get_id() << "] "
                  << "Scan failed: " << yrx_last_error() << std::endl;
    }
}

int main() {
    std::cout << "=== YARA-X CAPI Multi-threaded Demo ===" << std::endl;
    
    const char* yara_rule = R"(
        rule test_rule_1 {
            meta:
                description = "Test rule for pattern matching"
                author = "Demo"
            strings:
                $a = "Hello" nocase
                $b = "World" nocase
            condition:
                $a or $b
        }
        
        rule test_rule_2 {
            meta:
                description = "Test rule for hex pattern"
            strings:
                $hex = { 48 65 6C 6C 6F }  // "Hello" in hex
            condition:
                $hex
        }
        
        rule test_rule_3 {
            meta:
                description = "Test rule for regex"
            strings:
                $regex = /test.*pattern/i
            condition:
                $regex
        }
        
        rule always_match {
            condition:
                true
        }
    )";
    
    std::cout << "\n1. Compiling YARA rules..." << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    
    if (result != YRX_SUCCESS) {
        std::cerr << "Failed to create compiler: " << yrx_last_error() << std::endl;
        return 1;
    }
    
    result = yrx_compiler_add_source(compiler, yara_rule);
    if (result != YRX_SUCCESS) {
        std::cerr << "Failed to add source: " << yrx_last_error() << std::endl;
        yrx_compiler_destroy(compiler);
        return 1;
    }
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    if (rules == nullptr) {
        std::cerr << "Failed to build rules: " << yrx_last_error() << std::endl;
        return 1;
    }
    
    int rule_count = yrx_rules_count(rules);
    std::cout << "   Compiled " << rule_count << " rules successfully" << std::endl;
    
    std::cout << "\n2. Creating scanners for multi-threading..." << std::endl;
    
    const int num_threads = 4;
    std::vector<YRX_SCANNER*> scanners(num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        result = yrx_scanner_create(rules, &scanners[i]);
        if (result != YRX_SUCCESS) {
            std::cerr << "Failed to create scanner " << i << ": " << yrx_last_error() << std::endl;
            for (int j = 0; j < i; j++) {
                yrx_scanner_destroy(scanners[j]);
            }
            yrx_rules_destroy(rules);
            return 1;
        }
        std::cout << "   Created scanner " << i << std::endl;
    }
    
    std::cout << "\n3. Preparing test data..." << std::endl;
    
    std::vector<std::vector<uint8_t>> test_data = {
        std::vector<uint8_t>(std::begin("Hello World!"), std::end("Hello World!")),
        std::vector<uint8_t>(std::begin("This is a test pattern for YARA"), std::end("This is a test pattern for YARA")),
        std::vector<uint8_t>(std::begin("Random data without matches"), std::end("Random data without matches")),
        std::vector<uint8_t>(std::begin("HELLO from another thread"), std::end("HELLO from another thread"))
    };
    
    std::vector<std::string> data_names = {
        "data1.txt",
        "data2.txt", 
        "data3.txt",
        "data4.txt"
    };
    
    std::cout << "\n4. Starting multi-threaded scanning..." << std::endl;
    std::cout << "   Using " << num_threads << " threads" << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(scan_with_callback, scanners[i], 
                            std::ref(data_names[i]), std::ref(test_data[i]), i);
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "\n5. Scan results:" << std::endl;
    std::cout << "   Total matches across all threads: " << total_matches << std::endl;
    std::cout << "   Time taken: " << duration.count() << " ms" << std::endl;
    
    std::cout << "\n6. Demonstrating scanner reuse..." << std::endl;
    
    std::vector<uint8_t> additional_data(std::begin("Additional Hello World test"), 
                                        std::end("Additional Hello World test"));
    
    int additional_matches = 0;
    yrx_scanner_on_matching_rule(scanners[0], rule_callback, &additional_matches);
    
    std::cout << "   Reusing scanner 0 to scan additional data..." << std::endl;
    result = yrx_scanner_scan(scanners[0], additional_data.data(), additional_data.size());
    
    if (result == YRX_SUCCESS) {
        std::cout << "   Additional scan completed. Matches: " << additional_matches << std::endl;
    } else {
        std::cout << "   Additional scan failed: " << yrx_last_error() << std::endl;
    }
    
    std::cout << "\n7. Demonstrating timeout functionality..." << std::endl;
    
    YRX_SCANNER* timeout_scanner = nullptr;
    result = yrx_scanner_create(rules, &timeout_scanner);
    
    if (result == YRX_SUCCESS) {
        yrx_scanner_set_timeout(timeout_scanner, 1);
        std::cout << "   Scanner with 1 second timeout created" << std::endl;
        yrx_scanner_destroy(timeout_scanner);
    }
    
    std::cout << "\n8. Cleanup..." << std::endl;
    
    for (int i = 0; i < num_threads; i++) {
        yrx_scanner_destroy(scanners[i]);
        std::cout << "   Destroyed scanner " << i << std::endl;
    }
    
    yrx_rules_destroy(rules);
    std::cout << "   Destroyed rules" << std::endl;
    
    std::cout << "\n=== Demo completed successfully ===" << std::endl;
    std::cout << "Key takeaways:" << std::endl;
    std::cout << "- YRX_RULES can be shared across multiple scanners" << std::endl;
    std::cout << "- Each scanner can be used in a separate thread" << std::endl;
    std::cout << "- Scanners can be reused for multiple scans" << std::endl;
    std::cout << "- Always destroy scanners before destroying rules" << std::endl;
    
    return 0;
}
