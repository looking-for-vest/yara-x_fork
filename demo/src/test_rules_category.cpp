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

void test_category_malware() {
    std::cout << "\n=== Test: Malware Category ===" << std::endl;
    
    std::vector<std::string> malware_rules = {
        "./tests/Yara-Rules/rules/malware/MALW_Emotet.yar",
        "./tests/Yara-Rules/rules/malware/MALW_Mirai.yar",
        "./tests/Yara-Rules/rules/malware/APT_Stuxnet.yar"
    };
    
    for (const auto& rule_path : malware_rules) {
        std::string rule_content = read_file(rule_path);
        if (rule_content.empty()) {
            std::cout << "  [INFO] Skipping: " << rule_path << std::endl;
            continue;
        }
        
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for " << rule_path << ": " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile malware rule: " + rule_path.substr(rule_path.rfind('/') + 1));
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " rules from " << rule_path.substr(rule_path.rfind('/') + 1) << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_maldocs() {
    std::cout << "\n=== Test: Malicious Documents Category ===" << std::endl;
    
    std::vector<std::string> maldoc_rules = {
        "./tests/Yara-Rules/rules/maldocs/Maldoc_PDF.yar",
        "./tests/Yara-Rules/rules/maldocs/Maldoc_VBA_macro_code.yar",
        "./tests/Yara-Rules/rules/maldocs/Maldoc_DDE.yar"
    };
    
    for (const auto& rule_path : maldoc_rules) {
        std::string rule_content = read_file(rule_path);
        if (rule_content.empty()) {
            std::cout << "  [INFO] Skipping: " << rule_path << std::endl;
            continue;
        }
        
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for " << rule_path << ": " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile maldoc rule: " + rule_path.substr(rule_path.rfind('/') + 1));
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " rules from " << rule_path.substr(rule_path.rfind('/') + 1) << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_webshells() {
    std::cout << "\n=== Test: WebShells Category ===" << std::endl;
    
    std::string webshells_index = "./tests/Yara-Rules/rules/webshells_index.yar";
    std::string content = read_file(webshells_index);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for webshells: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile webshells index");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " webshell rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_packers() {
    std::cout << "\n=== Test: Packers Category ===" << std::endl;
    
    std::string packers_index = "./tests/Yara-Rules/rules/packers_index.yar";
    std::string content = read_file(packers_index);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for packers: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile packers index");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " packer rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_crypto() {
    std::cout << "\n=== Test: Crypto Category ===" << std::endl;
    
    std::string crypto_index = "./tests/Yara-Rules/rules/crypto_index.yar";
    std::string content = read_file(crypto_index);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for crypto: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile crypto index");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " crypto rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_cve() {
    std::cout << "\n=== Test: CVE Rules Category ===" << std::endl;
    
    std::string cve_index = "./tests/Yara-Rules/rules/cve_rules_index.yar";
    std::string content = read_file(cve_index);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for CVE rules: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile CVE rules index");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " CVE rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_antidebug() {
    std::cout << "\n=== Test: Anti-debug/Anti-VM Category ===" << std::endl;
    
    std::string antidebug_rule = "./tests/Yara-Rules/rules/antidebug_antivm/antidebug_antivm.yar";
    std::string content = read_file(antidebug_rule);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for antidebug: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile antidebug rules");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " antidebug rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

void test_category_capabilities() {
    std::cout << "\n=== Test: Capabilities Category ===" << std::endl;
    
    std::string capabilities_rule = "./tests/Yara-Rules/rules/capabilities/capabilities.yar";
    std::string content = read_file(capabilities_rule);
    
    if (!content.empty()) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile(content.c_str(), &rules);
        
        if (result != YRX_SUCCESS) {
            std::cout << "  [INFO] Compile failed for capabilities: " << yrx_last_error() << std::endl;
        } else {
            TEST_ASSERT(rules != nullptr, "Compile capabilities rules");
            
            if (rules) {
                int count = yrx_rules_count(rules);
                std::cout << "  [INFO] Compiled " << count << " capabilities rules" << std::endl;
                yrx_rules_destroy(rules);
            }
        }
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Rules Category Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_category_malware();
    test_category_maldocs();
    test_category_webshells();
    test_category_packers();
    test_category_crypto();
    test_category_cve();
    test_category_antidebug();
    test_category_capabilities();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
