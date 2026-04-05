#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>
#include <map>

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

struct MetadataInfo {
    std::string identifier;
    YRX_METADATA_TYPE type;
    std::string str_value;
    int64_t int_value;
    double float_value;
    bool bool_value;
};

struct RuleMetadata {
    std::string rule_name;
    std::vector<MetadataInfo> metadata_list;
};

void rule_callback(const YRX_RULE* rule, void* user_data) {
    std::vector<RuleMetadata>* results = static_cast<std::vector<RuleMetadata>*>(user_data);
    
    RuleMetadata rm;
    
    const uint8_t* ident = nullptr;
    size_t len = 0;
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        rm.rule_name = std::string(reinterpret_cast<const char*>(ident), len);
    }
    
    auto metadata_cb = [](const YRX_METADATA* metadata, void* user_data) {
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
    };
    
    yrx_rule_iter_metadata(rule, metadata_cb, &rm.metadata_list);
    results->push_back(rm);
}

void test_string_metadata() {
    std::cout << "\n=== Test: String Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule string_meta {
            meta:
                author = "Test Author"
                description = "This is a test rule"
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with string metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1) {
            TEST_ASSERT(results[0].rule_name == "string_meta", "Rule name is correct");
            TEST_ASSERT(results[0].metadata_list.size() == 2, "Two metadata entries");
            
            bool found_author = false;
            bool found_desc = false;
            for (const auto& m : results[0].metadata_list) {
                if (m.identifier == "author") {
                    found_author = true;
                    TEST_ASSERT(m.type == YRX_STRING, "author is string type");
                    TEST_ASSERT(m.str_value == "Test Author", "author value correct");
                }
                if (m.identifier == "description") {
                    found_desc = true;
                    TEST_ASSERT(m.type == YRX_STRING, "description is string type");
                }
            }
            TEST_ASSERT(found_author, "Found author metadata");
            TEST_ASSERT(found_desc, "Found description metadata");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_integer_metadata() {
    std::cout << "\n=== Test: Integer Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule int_meta {
            meta:
                version = 42
                count = 100
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with integer metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1 && results[0].metadata_list.size() >= 2) {
            bool found_version = false;
            bool found_count = false;
            for (const auto& m : results[0].metadata_list) {
                if (m.identifier == "version") {
                    found_version = true;
                    TEST_ASSERT(m.type == YRX_I64, "version is integer type");
                    TEST_ASSERT(m.int_value == 42, "version value is 42");
                }
                if (m.identifier == "count") {
                    found_count = true;
                    TEST_ASSERT(m.type == YRX_I64, "count is integer type");
                    TEST_ASSERT(m.int_value == 100, "count value is 100");
                }
            }
            TEST_ASSERT(found_version, "Found version metadata");
            TEST_ASSERT(found_count, "Found count metadata");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_float_metadata() {
    std::cout << "\n=== Test: Float Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule float_meta {
            meta:
                ratio = 3.14159
                threshold = 0.5
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with float metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1) {
            bool found_ratio = false;
            for (const auto& m : results[0].metadata_list) {
                if (m.identifier == "ratio") {
                    found_ratio = true;
                    TEST_ASSERT(m.type == YRX_F64, "ratio is float type");
                    TEST_ASSERT(m.float_value > 3.14 && m.float_value < 3.15, "ratio value is approximately 3.14159");
                }
            }
            TEST_ASSERT(found_ratio, "Found ratio metadata");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_boolean_metadata() {
    std::cout << "\n=== Test: Boolean Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule bool_meta {
            meta:
                enabled = true
                disabled = false
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with boolean metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1) {
            bool found_enabled = false;
            bool found_disabled = false;
            for (const auto& m : results[0].metadata_list) {
                if (m.identifier == "enabled") {
                    found_enabled = true;
                    TEST_ASSERT(m.type == YRX_BOOLEAN, "enabled is boolean type");
                    TEST_ASSERT(m.bool_value == true, "enabled value is true");
                }
                if (m.identifier == "disabled") {
                    found_disabled = true;
                    TEST_ASSERT(m.type == YRX_BOOLEAN, "disabled is boolean type");
                    TEST_ASSERT(m.bool_value == false, "disabled value is false");
                }
            }
            TEST_ASSERT(found_enabled, "Found enabled metadata");
            TEST_ASSERT(found_disabled, "Found disabled metadata");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_mixed_metadata() {
    std::cout << "\n=== Test: Mixed Metadata Types ===" << std::endl;
    
    const char* rule = R"(
        rule mixed_meta {
            meta:
                author = "Test"
                version = 1
                enabled = true
                ratio = 2.5
            strings:
                $a = "test"
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with mixed metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        
        const char* data = "test data";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1) {
            TEST_ASSERT(results[0].metadata_list.size() == 4, "Four metadata entries");
            
            std::map<std::string, YRX_METADATA_TYPE> types;
            for (const auto& m : results[0].metadata_list) {
                types[m.identifier] = m.type;
            }
            
            TEST_ASSERT(types["author"] == YRX_STRING, "author is string");
            TEST_ASSERT(types["version"] == YRX_I64, "version is integer");
            TEST_ASSERT(types["enabled"] == YRX_BOOLEAN, "enabled is boolean");
            TEST_ASSERT(types["ratio"] == YRX_F64, "ratio is float");
        }
        
        yrx_rules_destroy(rules);
    }
}

void test_no_metadata() {
    std::cout << "\n=== Test: No Metadata ===" << std::endl;
    
    const char* rule = R"(
        rule no_meta {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule without metadata");
    
    if (rules) {
        std::vector<RuleMetadata> results;
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, rule_callback, &results);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(results.size() == 1, "One rule matched");
        if (results.size() == 1) {
            TEST_ASSERT(results[0].metadata_list.empty(), "No metadata entries");
        }
        
        yrx_rules_destroy(rules);
    }
}

struct TagData {
    std::string rule_name;
    std::vector<std::string> tags;
};

void tag_callback(const char* tag, void* user_data) {
    TagData* data = static_cast<TagData*>(user_data);
    data->tags.push_back(tag);
}

void tag_rule_callback(const YRX_RULE* rule, void* user_data) {
    TagData* tag_data = static_cast<TagData*>(user_data);
    const uint8_t* ident = nullptr;
    size_t len = 0;
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        tag_data->rule_name = std::string(reinterpret_cast<const char*>(ident), len);
    }
    yrx_rule_iter_tags(rule, tag_callback, tag_data);
}

void test_tags() {
    std::cout << "\n=== Test: Tags ===" << std::endl;
    
    const char* rule = R"(
        rule tagged_rule : tag1 tag2 tag3 {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with tags");
    
    if (rules) {
        TagData tag_data;
        
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, tag_rule_callback, &tag_data);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(tag_data.rule_name == "tagged_rule", "Rule name correct");
        TEST_ASSERT(tag_data.tags.size() == 3, "Three tags found");
        
        bool found_tag1 = false, found_tag2 = false, found_tag3 = false;
        for (const auto& tag : tag_data.tags) {
            if (tag == "tag1") found_tag1 = true;
            if (tag == "tag2") found_tag2 = true;
            if (tag == "tag3") found_tag3 = true;
        }
        TEST_ASSERT(found_tag1 && found_tag2 && found_tag3, "All tags found");
        
        yrx_rules_destroy(rules);
    }
}

struct NamespaceData {
    std::string ns;
};

void namespace_rule_callback(const YRX_RULE* rule, void* user_data) {
    NamespaceData* ns_data = static_cast<NamespaceData*>(user_data);
    const uint8_t* ns = nullptr;
    size_t len = 0;
    if (yrx_rule_namespace(rule, &ns, &len) == YRX_SUCCESS) {
        ns_data->ns = std::string(reinterpret_cast<const char*>(ns), len);
    }
}

void test_namespace() {
    std::cout << "\n=== Test: Namespace ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_new_namespace(compiler, "custom_namespace");
    yrx_compiler_add_source(compiler, "rule namespaced { condition: true }");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    TEST_ASSERT(rules != nullptr, "Compile rule with namespace");
    
    if (rules) {
        NamespaceData ns_data;
        
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        yrx_scanner_on_matching_rule(scanner, namespace_rule_callback, &ns_data);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        yrx_scanner_destroy(scanner);
        
        TEST_ASSERT(ns_data.ns == "custom_namespace", "Namespace is correct");
        
        yrx_rules_destroy(rules);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Metadata Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_string_metadata();
    test_integer_metadata();
    test_float_metadata();
    test_boolean_metadata();
    test_mixed_metadata();
    test_no_metadata();
    test_tags();
    test_namespace();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
