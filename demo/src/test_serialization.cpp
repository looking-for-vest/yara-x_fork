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

void test_serialize_deserialize() {
    std::cout << "\n=== Test: Basic Serialize/Deserialize ===" << std::endl;
    
    const char* rule = R"(
        rule test_rule {
            strings:
                $a = "hello"
            condition:
                $a
        }
    )";
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile original rules");
    
    if (original_rules) {
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize rules");
        TEST_ASSERT(buffer != nullptr, "Buffer is not null");
        
        if (buffer) {
            TEST_ASSERT(buffer->data != nullptr, "Buffer data is not null");
            TEST_ASSERT(buffer->length > 0, "Buffer has data");
            
            std::cout << "    Serialized size: " << buffer->length << " bytes" << std::endl;
            
            YRX_RULES* deserialized_rules = nullptr;
            result = yrx_rules_deserialize(buffer->data, buffer->length, &deserialized_rules);
            TEST_ASSERT(result == YRX_SUCCESS, "Deserialize rules");
            TEST_ASSERT(deserialized_rules != nullptr, "Deserialized rules not null");
            
            if (deserialized_rules) {
                int count = yrx_rules_count(deserialized_rules);
                TEST_ASSERT(count == 1, "Deserialized rule count is 1");
                
                const char* data = "hello world";
                ScanResult scan_result = {0, {}};
                YRX_SCANNER* scanner = nullptr;
                yrx_scanner_create(deserialized_rules, &scanner);
                yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
                yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
                yrx_scanner_destroy(scanner);
                
                TEST_ASSERT(scan_result.match_count == 1, "Deserialized rules work correctly");
                
                yrx_rules_destroy(deserialized_rules);
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

void test_serialize_multiple_rules() {
    std::cout << "\n=== Test: Serialize Multiple Rules ===" << std::endl;
    
    const char* rule = R"(
        rule rule1 { condition: true }
        rule rule2 { condition: true }
        rule rule3 { condition: true }
        rule rule4 { strings: $a = "test" condition: $a }
        rule rule5 { strings: $a = "hello" nocase condition: $a }
    )";
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile multiple rules");
    
    if (original_rules) {
        int original_count = yrx_rules_count(original_rules);
        TEST_ASSERT(original_count == 5, "Original rule count is 5");
        
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize multiple rules");
        
        if (buffer) {
            YRX_RULES* deserialized_rules = nullptr;
            result = yrx_rules_deserialize(buffer->data, buffer->length, &deserialized_rules);
            TEST_ASSERT(result == YRX_SUCCESS, "Deserialize multiple rules");
            
            if (deserialized_rules) {
                int deserialized_count = yrx_rules_count(deserialized_rules);
                TEST_ASSERT(deserialized_count == original_count, "Rule count preserved");
                
                yrx_rules_destroy(deserialized_rules);
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

void test_serialize_with_patterns() {
    std::cout << "\n=== Test: Serialize With Complex Patterns ===" << std::endl;
    
    const char* rule = R"(
        rule complex_patterns {
            strings:
                $str = "hello world"
                $hex = { 48 65 6C 6C 6F }
                $re = /test.*pattern/i
            condition:
                any of them
        }
    )";
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile complex patterns");
    
    if (original_rules) {
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize complex patterns");
        
        if (buffer) {
            YRX_RULES* deserialized_rules = nullptr;
            result = yrx_rules_deserialize(buffer->data, buffer->length, &deserialized_rules);
            TEST_ASSERT(result == YRX_SUCCESS, "Deserialize complex patterns");
            
            if (deserialized_rules) {
                const char* data = "hello world";
                ScanResult scan_result = {0, {}};
                YRX_SCANNER* scanner = nullptr;
                yrx_scanner_create(deserialized_rules, &scanner);
                yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
                yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
                yrx_scanner_destroy(scanner);
                
                TEST_ASSERT(scan_result.match_count == 1, "Complex patterns work after deserialize");
                
                yrx_rules_destroy(deserialized_rules);
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

struct MetaData {
    std::string author;
    int version;
    bool enabled;
    int count;
};

void serialize_meta_callback(const YRX_METADATA* m, void* user_data) {
    MetaData* meta = static_cast<MetaData*>(user_data);
    meta->count++;
    
    std::string ident = m->identifier;
    if (ident == "author") {
        meta->author = m->value.string;
    } else if (ident == "version") {
        meta->version = m->value.i64;
    } else if (ident == "enabled") {
        meta->enabled = m->value.boolean;
    }
}

void serialize_rule_callback(const YRX_RULE* rule, void* user_data) {
    MetaData* meta = static_cast<MetaData*>(user_data);
    yrx_rule_iter_metadata(rule, serialize_meta_callback, meta);
}

void test_serialize_with_metadata() {
    std::cout << "\n=== Test: Serialize With Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule with_metadata {
            meta:
                author = "Test"
                version = 1
                enabled = true
            condition:
                true
        }
    )";
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile with metadata");
    
    if (original_rules) {
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize with metadata");
        
        if (buffer) {
            YRX_RULES* deserialized_rules = nullptr;
            result = yrx_rules_deserialize(buffer->data, buffer->length, &deserialized_rules);
            TEST_ASSERT(result == YRX_SUCCESS, "Deserialize with metadata");
            
            if (deserialized_rules) {
                MetaData meta = {"", 0, false, 0};
                
                YRX_SCANNER* scanner = nullptr;
                yrx_scanner_create(deserialized_rules, &scanner);
                yrx_scanner_on_matching_rule(scanner, serialize_rule_callback, &meta);
                yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
                yrx_scanner_destroy(scanner);
                
                TEST_ASSERT(meta.count == 3, "Metadata count preserved");
                TEST_ASSERT(meta.author == "Test", "Author metadata preserved");
                TEST_ASSERT(meta.version == 1, "Version metadata preserved");
                TEST_ASSERT(meta.enabled == true, "Enabled metadata preserved");
                
                yrx_rules_destroy(deserialized_rules);
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

void test_serialize_large_ruleset() {
    std::cout << "\n=== Test: Serialize Large Rule Set ===" << std::endl;
    
    std::string rules;
    for (int i = 0; i < 100; i++) {
        rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
    }
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rules.c_str(), &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile 100 rules");
    
    if (original_rules) {
        int original_count = yrx_rules_count(original_rules);
        TEST_ASSERT(original_count == 100, "Original count is 100");
        
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize large ruleset");
        
        if (buffer) {
            std::cout << "    Serialized 100 rules: " << buffer->length << " bytes" << std::endl;
            
            YRX_RULES* deserialized_rules = nullptr;
            result = yrx_rules_deserialize(buffer->data, buffer->length, &deserialized_rules);
            TEST_ASSERT(result == YRX_SUCCESS, "Deserialize large ruleset");
            
            if (deserialized_rules) {
                int deserialized_count = yrx_rules_count(deserialized_rules);
                TEST_ASSERT(deserialized_count == 100, "Deserialized count is 100");
                
                yrx_rules_destroy(deserialized_rules);
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

void test_deserialize_invalid_data() {
    std::cout << "\n=== Test: Deserialize Invalid Data ===" << std::endl;
    
    uint8_t invalid_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_rules_deserialize(invalid_data, sizeof(invalid_data), &rules);
    
    TEST_ASSERT(result != YRX_SUCCESS, "Deserialize invalid data fails");
    TEST_ASSERT(rules == nullptr, "Rules is null on failure");
    
    std::cout << "    Error: " << yrx_last_error() << std::endl;
}

void test_serialize_to_file() {
    std::cout << "\n=== Test: Serialize To/From File ===" << std::endl;
    
    const char* rule = R"(
        rule file_test {
            strings:
                $a = "test"
            condition:
                $a
        }
    )";
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rules");
    
    if (original_rules) {
        YRX_BUFFER* buffer = nullptr;
        result = yrx_rules_serialize(original_rules, &buffer);
        TEST_ASSERT(result == YRX_SUCCESS, "Serialize rules");
        
        if (buffer) {
            FILE* f = fopen("tests/data/serialized_rules.bin", "wb");
            if (f) {
                size_t written = fwrite(buffer->data, 1, buffer->length, f);
                fclose(f);
                
                TEST_ASSERT(written == buffer->length, "Write to file successful");
                
                f = fopen("tests/data/serialized_rules.bin", "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long file_size = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    
                    std::vector<uint8_t> file_data(file_size);
                    size_t read_size = fread(file_data.data(), 1, file_size, f);
                    fclose(f);
                    
                    TEST_ASSERT(read_size == (size_t)file_size, "Read from file successful");
                    
                    YRX_RULES* loaded_rules = nullptr;
                    result = yrx_rules_deserialize(file_data.data(), file_data.size(), &loaded_rules);
                    TEST_ASSERT(result == YRX_SUCCESS, "Deserialize from file");
                    
                    if (loaded_rules) {
                        int count = yrx_rules_count(loaded_rules);
                        TEST_ASSERT(count == 1, "Loaded rule count correct");
                        
                        yrx_rules_destroy(loaded_rules);
                    }
                }
            } else {
                std::cout << "    [INFO] Could not create file for test" << std::endl;
            }
            
            yrx_buffer_destroy(buffer);
        }
        
        yrx_rules_destroy(original_rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Serialization Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_serialize_deserialize();
    test_serialize_multiple_rules();
    test_serialize_with_patterns();
    test_serialize_with_metadata();
    test_serialize_large_ruleset();
    test_deserialize_invalid_data();
    test_serialize_to_file();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
