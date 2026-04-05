#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

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

namespace fs = std::filesystem;

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
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return "";
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

void test_malware_samples() {
    std::cout << "\n=== Test: Malware Samples ===" << std::endl;
    
    // 测试恶意软件样本
    std::string malware_rule_path = "./tests/Yara-Rules/rules/malware/MALW_Emotet.yar";
    std::string rule_content = read_file(malware_rule_path);
    
    TEST_ASSERT(!rule_content.empty(), "Read malware rule file");
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
    
    if (result == YRX_SUCCESS && rules) {
        TEST_ASSERT(rules != nullptr, "Compile malware rules");
        
        // 测试样本目录
        std::string samples_dir = "./tests/samples";
        
        if (fs::exists(samples_dir) && fs::is_directory(samples_dir)) {
            for (const auto& entry : fs::directory_iterator(samples_dir)) {
                if (entry.is_regular_file()) {
                    std::string sample_path = entry.path().string();
                    std::string sample_content = read_file(sample_path);
                    
                    if (!sample_content.empty()) {
                        YRX_SCANNER* scanner = nullptr;
                        yrx_scanner_create(rules, &scanner);
                        
                        if (scanner) {
                            ScanResult scan_result = {0, {}};
                            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
                            
                            result = yrx_scanner_scan(scanner, 
                                                     reinterpret_cast<const uint8_t*>(sample_content.c_str()), 
                                                     sample_content.size());
                            
                            TEST_ASSERT(result == YRX_SUCCESS, "Scan malware sample: " + entry.path().filename().string());
                            
                            if (scan_result.match_count > 0) {
                                std::cout << "  [INFO] Sample " << entry.path().filename().string() << " matched " << scan_result.match_count << " rules:" << std::endl;
                                for (const auto& rule : scan_result.matched_rules) {
                                    std::cout << "    - " << rule << std::endl;
                                }
                            } else {
                                std::cout << "  [INFO] Sample " << entry.path().filename().string() << " matched no rules" << std::endl;
                            }
                            
                            yrx_scanner_destroy(scanner);
                        }
                    }
                }
            }
        } else {
            std::cout << "  [INFO] Samples directory not found, skipping sample tests" << std::endl;
            TEST_ASSERT(true, "Samples directory check");
        }
        
        yrx_rules_destroy(rules);
    } else {
        std::cout << "  [INFO] Failed to compile malware rules: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile malware rules");
    }
}

void test_maldoc_samples() {
    std::cout << "\n=== Test: Malicious Document Samples ===" << std::endl;
    
    // 测试恶意文档样本
    std::string maldoc_rule_path = "./tests/Yara-Rules/rules/maldocs/Maldoc_PDF.yar";
    std::string rule_content = read_file(maldoc_rule_path);
    
    TEST_ASSERT(!rule_content.empty(), "Read maldoc rule file");
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
    
    if (result == YRX_SUCCESS && rules) {
        TEST_ASSERT(rules != nullptr, "Compile maldoc rules");
        
        // 测试PDF样本
        std::string pdf_sample = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000101 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\n%%EOF";
        
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        if (scanner) {
            ScanResult scan_result = {0, {}};
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            
            result = yrx_scanner_scan(scanner, 
                                     reinterpret_cast<const uint8_t*>(pdf_sample.c_str()), 
                                     pdf_sample.size());
            
            TEST_ASSERT(result == YRX_SUCCESS, "Scan PDF sample");
            
            if (scan_result.match_count > 0) {
                std::cout << "  [INFO] PDF sample matched " << scan_result.match_count << " rules:" << std::endl;
                for (const auto& rule : scan_result.matched_rules) {
                    std::cout << "    - " << rule << std::endl;
                }
            } else {
                std::cout << "  [INFO] PDF sample matched no rules" << std::endl;
            }
            
            yrx_scanner_destroy(scanner);
        }
        
        yrx_rules_destroy(rules);
    } else {
        std::cout << "  [INFO] Failed to compile maldoc rules: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile maldoc rules");
    }
}

void test_webshell_samples() {
    std::cout << "\n=== Test: WebShell Samples ===" << std::endl;
    
    // 测试WebShell样本
    std::string webshell_rule = R"(
        rule webshell_test {
            strings:
                $php_eval = "eval(" nocase
                $php_exec = "exec(" nocase
                $php_system = "system(" nocase
            condition:
                any of them
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(webshell_rule.c_str(), &rules);
    
    if (result == YRX_SUCCESS && rules) {
        TEST_ASSERT(rules != nullptr, "Compile webshell rules");
        
        // 测试PHP webshell样本
        std::string php_webshell = "<?php eval($_POST['cmd']); ?>";
        
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        if (scanner) {
            ScanResult scan_result = {0, {}};
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            
            result = yrx_scanner_scan(scanner, 
                                     reinterpret_cast<const uint8_t*>(php_webshell.c_str()), 
                                     php_webshell.size());
            
            TEST_ASSERT(result == YRX_SUCCESS, "Scan PHP webshell sample");
            TEST_ASSERT(scan_result.match_count > 0, "PHP webshell sample should match");
            
            if (scan_result.match_count > 0) {
                std::cout << "  [INFO] PHP webshell sample matched " << scan_result.match_count << " rules:" << std::endl;
                for (const auto& rule : scan_result.matched_rules) {
                    std::cout << "    - " << rule << std::endl;
                }
            }
            
            yrx_scanner_destroy(scanner);
        }
        
        yrx_rules_destroy(rules);
    } else {
        std::cout << "  [INFO] Failed to compile webshell rules: " << yrx_last_error() << std::endl;
        TEST_ASSERT(false, "Compile webshell rules");
    }
}

void test_real_world_rules() {
    std::cout << "\n=== Test: Real World Rules ===" << std::endl;
    
    // 测试真实世界的规则
    std::vector<std::string> rule_files = {
        "./tests/Yara-Rules/rules/malware/MALW_Mirai.yar",
        "./tests/Yara-Rules/rules/antidebug_antivm/antidebug_antivm.yar",
        "./tests/Yara-Rules/rules/capabilities/capabilities.yar"
    };
    
    for (const auto& rule_path : rule_files) {
        std::string rule_content = read_file(rule_path);
        if (rule_content.empty()) {
            std::cout << "  [INFO] Skipping: " << rule_path << std::endl;
            continue;
        }
        
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
        
        if (result == YRX_SUCCESS && rules) {
            int count = yrx_rules_count(rules);
            std::cout << "  [INFO] Compiled " << count << " rules from " << rule_path.substr(rule_path.rfind('/') + 1) << std::endl;
            TEST_ASSERT(count > 0, "Compile real world rules: " + rule_path.substr(rule_path.rfind('/') + 1));
            
            // 测试扫描性能
            std::string test_data = "This is a test string with some potential malicious content.";
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            
            if (scanner) {
                ScanResult scan_result = {0, {}};
                yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
                
                result = yrx_scanner_scan(scanner, 
                                         reinterpret_cast<const uint8_t*>(test_data.c_str()), 
                                         test_data.size());
                
                TEST_ASSERT(result == YRX_SUCCESS, "Scan with real world rules");
                
                if (scan_result.match_count > 0) {
                    std::cout << "  [INFO] Test data matched " << scan_result.match_count << " rules" << std::endl;
                }
                
                yrx_scanner_destroy(scanner);
            }
            
            yrx_rules_destroy(rules);
        } else {
            std::cout << "  [INFO] Failed to compile " << rule_path << ": " << yrx_last_error() << std::endl;
            TEST_ASSERT(false, "Compile real world rules: " + rule_path.substr(rule_path.rfind('/') + 1));
        }
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Integration Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_malware_samples();
    test_maldoc_samples();
    test_webshell_samples();
    test_real_world_rules();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
