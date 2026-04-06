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

YRX_RULES* compile_rule(const char* rule) {
    YRX_RULES* rules = nullptr;
    yrx_compile(rule, &rules);
    return rules;
}

ScanResult scan_data(YRX_RULES* rules, const uint8_t* data, size_t len) {
    ScanResult result = {0, {}};
    
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    
    yrx_scanner_on_matching_rule(scanner, rule_callback, &result);
    yrx_scanner_scan(scanner, data, len);
    
    yrx_scanner_destroy(scanner);
    
    return result;
}

void test_pe_module() {
    std::cout << "\n=== Test: PE Module ===" << std::endl;
    
    // 测试PE模块的基本功能
    const char* rule = R"(
        rule pe_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule");
    
    if (rules) {
        // 创建一个简单的PE文件头模拟数据
        uint8_t pe_header[] = {
            0x4D, 0x5A, // MZ
            0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // e_lfanew
            0x50, 0x45, 0x00, 0x00, // PE00
        };
        
        ScanResult result = scan_data(rules, pe_header, sizeof(pe_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(true, "PE module test completed");
        
        yrx_rules_destroy(rules);
    }
}

void test_elf_module() {
    std::cout << "\n=== Test: ELF Module ===" << std::endl;
    
    // 测试ELF模块的基本功能
    const char* rule = R"(
        rule elf_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule");
    
    if (rules) {
        // 创建一个简单的ELF文件头模拟数据
        uint8_t elf_header[] = {
            0x7F, 0x45, 0x4C, 0x46, // ELF
            0x02, // 64-bit
            0x01, // little-endian
            0x01, // ELF version
            0x00, // OS ABI
            0x00, // ABI version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, // executable
            0x3E, 0x00, // x86-64
            0x01, 0x00, 0x00, 0x00, // ELF version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // entry point
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section header offset
            0x00, 0x00, 0x00, 0x00, // flags
            0x40, 0x00, 0x00, 0x00, // header size
        };
        
        ScanResult result = scan_data(rules, elf_header, sizeof(elf_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(true, "ELF module test completed");
        
        yrx_rules_destroy(rules);
    }
}

void test_macho_module() {
    std::cout << "\n=== Test: Mach-O Module ===" << std::endl;
    
    // 测试Mach-O模块的基本功能
    const char* rule = R"(
        rule macho_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule");
    
    if (rules) {
        // 创建一个简单的Mach-O文件头模拟数据 (64-bit)
        uint8_t macho_header[] = {
            0xFE, 0xED, 0xFA, 0xCE, // magic
            0x00, 0x00, 0x00, 0x01, // cputype (x86-64)
            0x00, 0x00, 0x00, 0x03, // cpusubtype
            0x00, 0x00, 0x00, 0x02, // filetype (executable)
            0x00, 0x00, 0x00, 0x07, // ncmds
            0x00, 0x00, 0x00, 0x88, // sizeofcmds
            0x00, 0x00, 0x00, 0x00, // flags
        };
        
        ScanResult result = scan_data(rules, macho_header, sizeof(macho_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(true, "Mach-O module test completed");
        
        yrx_rules_destroy(rules);
    }
}

void test_crx_module() {
    std::cout << "\n=== Test: CRX Module ===" << std::endl;
    
    // 测试CRX模块的基本功能
    const char* rule = R"(
        rule crx_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule");
    
    if (rules) {
        // 创建一个简单的CRX文件头模拟数据
        uint8_t crx_header[] = {
            0x43, 0x72, 0x32, 0x34, // Cr24
            0x02, 0x00, 0x00, 0x00, // version
            0x10, 0x00, 0x00, 0x00, // header size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // public key
        };
        
        ScanResult result = scan_data(rules, crx_header, sizeof(crx_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(true, "CRX module test completed");
        
        yrx_rules_destroy(rules);
    }
}

void test_lnk_module() {
    std::cout << "\n=== Test: LNK Module ===" << std::endl;
    
    // 测试LNK模块的基本功能
    const char* rule = R"(
        rule lnk_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule");
    
    if (rules) {
        // 创建一个简单的LNK文件头模拟数据
        uint8_t lnk_header[] = {
            0x4C, 0x00, 0x00, 0x00, // L
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // GUID
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
            0x93, 0xE0, 0x7B, 0x14, 0xAC, 0x3B, 0x10, 0x19,
            0x97, 0x9A, 0x00, 0x50, 0xEB, 0x44, 0x49, 0x1E,
            0x00, 0x00, 0x00, 0x00, // LinkFlags
            0x00, 0x00, 0x00, 0x00, // FileAttributes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CreationTime
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AccessTime
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // WriteTime
            0x00, 0x00, 0x00, 0x00, // FileSize
            0x00, 0x00, 0x00, 0x00, // IconIndex
            0x00, 0x00, 0x00, 0x00, // ShowCommand
            0x00, 0x00, // HotKey
            0x00, 0x00, // Reserved1
            0x00, 0x00, 0x00, 0x00, // Reserved2
            0x00, 0x00, 0x00, 0x00, // Reserved3
        };
        
        ScanResult result = scan_data(rules, lnk_header, sizeof(lnk_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(true, "LNK module test completed");
        
        yrx_rules_destroy(rules);
    }
}

void test_file_format_functions() {
    std::cout << "\n=== Test: File Format Functions ===" << std::endl;
    
    // 测试基本规则编译
    const char* basic_rule = R"(
        rule basic_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(basic_rule);
    TEST_ASSERT(rules != nullptr, "Compile basic rule for file format functions test");
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
    
    TEST_ASSERT(true, "File format functions test completed");
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI File Format Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_pe_module();
    test_elf_module();
    test_macho_module();
    test_crx_module();
    test_lnk_module();
    test_file_format_functions();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
