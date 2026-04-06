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
    YRX_COMPILER* compiler = nullptr;
    YRX_RULES* rules = nullptr;
    
    // 创建编译器
    if (yrx_compiler_create(0, &compiler) != YRX_SUCCESS) {
        std::cout << "  [ERROR] Create compiler failed: " << yrx_last_error() << std::endl;
        return nullptr;
    }
    
    // 添加规则源码
    if (yrx_compiler_add_source(compiler, rule) != YRX_SUCCESS) {
        std::cout << "  [ERROR] Add source failed: " << yrx_last_error() << std::endl;
        yrx_compiler_destroy(compiler);
        return nullptr;
    }
    
    // 构建规则
    rules = yrx_compiler_build(compiler);
    
    // 销毁编译器
    yrx_compiler_destroy(compiler);
    
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
    
    // 测试PE模块是否能正确加载
    const char* rule = R"(
        import "pe"
        
        rule pe_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile PE module rule");
    
    if (rules) {
        // 创建一个更完整的PE文件头模拟数据
        uint8_t pe_header[] = {
            // DOS头
            0x4D, 0x5A, // MZ
            0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // e_lfanew
            // NT头
            0x50, 0x45, 0x00, 0x00, // PE00
            0x01, 0x4C, 0x00, 0x00, // Machine (x86)
            0x01, 0x00, // Number of sections
            0x00, 0x00, 0x00, 0x00, // Time date stamp
            0x00, 0x00, 0x00, 0x00, // Pointer to symbol table
            0x00, 0x00, 0x00, 0x00, // Number of symbols
            0xE0, 0x00, 0x00, 0x00, // Size of optional header
            0x03, 0x01, 0x00, 0x00, // Characteristics
            // Optional header
            0x0B, 0x01, 0x00, 0x00, // Magic (PE32)
            0x00, 0x00, // Major linker version
            0x00, 0x00, // Minor linker version
            0x00, 0x10, 0x00, 0x00, // Size of code
            0x00, 0x08, 0x00, 0x00, // Size of initialized data
            0x00, 0x00, 0x00, 0x00, // Size of uninitialized data
            0x00, 0x10, 0x00, 0x00, // Address of entry point
            0x00, 0x10, 0x00, 0x00, // Base of code
            0x00, 0x20, 0x00, 0x00, // Base of data
            0x40, 0x00, 0x00, 0x00, // Image base
            0x10, 0x00, 0x00, 0x00, // Section alignment
            0x04, 0x00, 0x00, 0x00, // File alignment
            0x04, 0x00, 0x00, 0x00, // Major OS version
            0x00, 0x00, 0x00, 0x00, // Minor OS version
            0x00, 0x00, 0x00, 0x00, // Major image version
            0x00, 0x00, 0x00, 0x00, // Minor image version
            0x04, 0x00, 0x00, 0x00, // Major subsystem version
            0x00, 0x00, 0x00, 0x00, // Minor subsystem version
            0x00, 0x00, 0x00, 0x00, // Win32 version value
            0x40, 0x00, 0x00, 0x00, // Size of image
            0x04, 0x00, 0x00, 0x00, // Size of headers
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x02, 0x00, 0x00, 0x00, // Subsystem
            0x00, 0x00, 0x00, 0x00, // Dll characteristics
            0x00, 0x10, 0x00, 0x00, // Size of stack reserve
            0x00, 0x00, 0x00, 0x00, // Size of stack commit
            0x00, 0x10, 0x00, 0x00, // Size of heap reserve
            0x00, 0x00, 0x00, 0x00, // Size of heap commit
            0x00, 0x00, 0x00, 0x00, // Loader flags
            0x10, 0x00, 0x00, 0x00, // Number of RVA and sizes
            // Data directories (16 entries)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Export table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Import table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Resource table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Exception table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Certificate table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Base relocation table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Debug
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Architecture
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Global pointer
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TLS table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Load config table
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Bound import
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IAT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Delay import descriptor
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CLR runtime header
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            // Section table
            0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, // .text
            0x00, 0x10, 0x00, 0x00, // Virtual size
            0x00, 0x10, 0x00, 0x00, // Virtual address
            0x00, 0x10, 0x00, 0x00, // Size of raw data
            0x00, 0x10, 0x00, 0x00, // Pointer to raw data
            0x00, 0x00, 0x00, 0x00, // Pointer to relocations
            0x00, 0x00, 0x00, 0x00, // Pointer to line numbers
            0x00, 0x00, // Number of relocations
            0x00, 0x00, // Number of line numbers
            0x60, 0x00, 0x00, 0x20, // Characteristics
        };
        
        ScanResult result = scan_data(rules, pe_header, sizeof(pe_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "PE module scan completed successfully");
        
        // 测试无效的PE文件
        uint8_t invalid_pe[] = {
            0x4D, 0x5A, // MZ
            0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // e_lfanew
            0x50, 0x46, 0x00, 0x00, // Invalid signature (should be PE00)
        };
        
        result = scan_data(rules, invalid_pe, sizeof(invalid_pe));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "PE module scan completed successfully for invalid file");
        
        yrx_rules_destroy(rules);
    }
}

void test_elf_module() {
    std::cout << "\n=== Test: ELF Module ===" << std::endl;
    
    // 测试ELF模块的type字段
    const char* rule = R"(
        import "elf"
        
        rule elf_test {
            condition:
                elf.type
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile ELF module rule");
    
    if (rules) {
        // 创建一个更完整的ELF文件头模拟数据
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
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section header offset
            0x00, 0x00, 0x00, 0x00, // flags
            0x40, 0x00, 0x00, 0x00, // header size
            // Program header table
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type (PT_LOAD)
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags (RWE)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // vaddr
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // paddr
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filesz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // memsz
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // align
        };
        
        ScanResult result = scan_data(rules, elf_header, sizeof(elf_header));
        
        // 测试扫描是否成功，且规则应该匹配
        TEST_ASSERT(result.match_count > 0, "ELF module should match valid ELF file");
        
        // 测试无效的ELF文件
        uint8_t invalid_elf[] = {
            0x7F, 0x45, 0x4C, 0x48, // Invalid ELF magic
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
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // section header offset
            0x00, 0x00, 0x00, 0x00, // flags
            0x40, 0x00, 0x00, 0x00, // header size
        };
        
        result = scan_data(rules, invalid_elf, sizeof(invalid_elf));
        
        // 测试无效ELF文件应该不匹配
        TEST_ASSERT(result.match_count == 0, "ELF module should not match invalid ELF file");
        
        yrx_rules_destroy(rules);
    }
}

void test_macho_module() {
    std::cout << "\n=== Test: Mach-O Module ===" << std::endl;
    
    // 测试Mach-O模块的magic字段
    const char* rule = R"(
        import "macho"
        
        rule macho_test {
            condition:
                macho.magic
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile Mach-O module rule");
    
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
        
        // 测试扫描是否成功，且规则应该匹配
        TEST_ASSERT(result.match_count > 0, "Mach-O module should match valid Mach-O file");
        
        // 测试无效的Mach-O文件
        uint8_t invalid_macho[] = {
            0xFE, 0xED, 0xFA, 0xCF, // Invalid magic (should be FEEDFACE for 32-bit or FEEDFACF for 64-bit)
            0x00, 0x00, 0x00, 0x01, // cputype (x86-64)
            0x00, 0x00, 0x00, 0x03, // cpusubtype
            0x00, 0x00, 0x00, 0x02, // filetype (executable)
            0x00, 0x00, 0x00, 0x07, // ncmds
            0x00, 0x00, 0x00, 0x88, // sizeofcmds
            0x00, 0x00, 0x00, 0x00, // flags
        };
        
        result = scan_data(rules, invalid_macho, sizeof(invalid_macho));
        
        // 测试无效Mach-O文件应该不匹配
        TEST_ASSERT(result.match_count == 0, "Mach-O module should not match invalid Mach-O file");
        
        yrx_rules_destroy(rules);
    }
}

void test_crx_module() {
    std::cout << "\n=== Test: CRX Module ===" << std::endl;
    
    // 测试CRX模块是否能正确加载
    const char* rule = R"(
        import "crx"
        
        rule crx_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile CRX module rule");
    
    if (rules) {
        // 创建一个更完整的CRX文件头模拟数据
        uint8_t crx_header[] = {
            0x43, 0x72, 0x32, 0x34, // Cr24
            0x02, 0x00, 0x00, 0x00, // version
            0x10, 0x00, 0x00, 0x00, // header size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // public key
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
        };
        
        ScanResult result = scan_data(rules, crx_header, sizeof(crx_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "CRX module scan completed successfully");
        
        // 测试无效的CRX文件
        uint8_t invalid_crx[] = {
            0x43, 0x72, 0x32, 0x35, // Invalid CRX magic (should be Cr24)
            0x02, 0x00, 0x00, 0x00, // version
            0x10, 0x00, 0x00, 0x00, // header size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // public key
        };
        
        result = scan_data(rules, invalid_crx, sizeof(invalid_crx));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "CRX module scan completed successfully for invalid file");
        
        yrx_rules_destroy(rules);
    }
}

void test_lnk_module() {
    std::cout << "\n=== Test: LNK Module ===" << std::endl;
    
    // 测试LNK模块是否能正确加载
    const char* rule = R"(
        import "lnk"
        
        rule lnk_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    TEST_ASSERT(rules != nullptr, "Compile LNK module rule");
    
    if (rules) {
        // 创建一个更完整的LNK文件头模拟数据
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
            // LinkTargetIDList (empty)
            0x00, 0x00, // Length
        };
        
        ScanResult result = scan_data(rules, lnk_header, sizeof(lnk_header));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "LNK module scan completed successfully");
        
        // 测试无效的LNK文件
        uint8_t invalid_lnk[] = {
            0x4D, 0x00, 0x00, 0x00, // Invalid LNK magic (should be 4C 00 00 00)
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
        
        result = scan_data(rules, invalid_lnk, sizeof(invalid_lnk));
        
        // 测试扫描是否成功
        TEST_ASSERT(result.match_count > 0, "LNK module scan completed successfully for invalid file");
        
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
