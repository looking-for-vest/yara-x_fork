# test_functionality.cpp 解读

## 背景说明

本文档面向不熟悉 C++ 语法和 YARA-X 接口的用户，旨在详细解释 `test_functionality.cpp` 文件的功能和实现，帮助用户理解 YARA-X CAPI 库的核心功能。

## 功能概述

`test_functionality.cpp` 是一个功能验证测试模块，用于测试 YARA-X CAPI 库的核心功能。该测试模块验证库的模式匹配、元数据处理、全局变量管理、规则标签和命名空间等功能，确保库的基本功能正常工作。

## 主要测试内容

### 1. 模式匹配测试 (`test_pattern_matching`)

- **功能**：测试各种模式匹配功能
- **实现步骤**：
  - 测试字符串模式匹配（不区分大小写）
  - 测试十六进制模式匹配
  - 测试正则表达式模式匹配
  - 验证所有模式匹配都能正确工作

### 2. 元数据处理测试 (`test_metadata_handling`)

- **功能**：测试元数据处理功能
- **实现步骤**：
  - 测试字符串、整数、浮点数和布尔类型元数据
  - 测试元数据计数
  - 测试元数据值的获取和验证
  - 验证所有元数据都能正确处理

### 3. 全局变量测试 (`test_global_variables`)

- **功能**：测试全局变量功能
- **实现步骤**：
  - 测试编译器级别的全局变量定义
  - 测试扫描器级别的全局变量修改
  - 测试全局变量在条件中的使用
  - 验证全局变量功能正常工作

### 4. 规则标签测试 (`test_rule_tags`)

- **功能**：测试规则标签功能
- **实现步骤**：
  - 测试带标签的规则编译
  - 测试标签计数
  - 测试标签的获取和验证
  - 验证标签功能正常工作

### 5. 命名空间测试 (`test_namespaces`)

- **功能**：测试命名空间功能
- **实现步骤**：
  - 测试命名空间的创建
  - 测试规则添加到命名空间
  - 测试命名空间的验证
  - 验证命名空间功能正常工作

## 核心代码解析

### 1. 标签回调函数

```cpp
void tag_callback(const uint8_t* tag, size_t len, void* user_data) {
    std::vector<std::string>* tags = static_cast<std::vector<std::string>*>(user_data);
    std::string tag_str(reinterpret_cast<const char*>(tag), len);
    tags->push_back(tag_str);
}
```
- **说明**：当 YARA-X 迭代规则标签时，会调用这个函数
- **参数解释**：
  - `tag`：标签字符串指针
  - `len`：标签长度
  - `user_data`：用户数据指针，用于传递标签向量
- **功能**：将标签转换为字符串并添加到标签向量中

### 2. 带标签的规则回调函数

```cpp
void rule_with_tags_callback(const YRX_RULE* rule, void* user_data) {
    std::vector<std::string>* matched_rules = static_cast<std::vector<std::string>*>(user_data);
    
    const uint8_t* ident = nullptr;
    size_t len = 0;
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        std::string name(reinterpret_cast<const char*>(ident), len);
        matched_rules->push_back(name);
    }
}
```
- **说明**：当 YARA-X 扫描到匹配的规则时，会调用这个函数
- **参数解释**：
  - `rule`：匹配的规则指针
  - `user_data`：用户数据指针，用于传递匹配规则向量
- **功能**：获取匹配规则的名称并添加到匹配规则向量中

### 3. 模式匹配测试实现

```cpp
void test_pattern_matching() {
    std::cout << "\n=== Test: Pattern Matching ===" << std::endl;
    
    // 测试字符串模式
    const char* string_rule = R"(
        rule test_string {
            strings:
                $s = "Hello" nocase  // 不区分大小写的字符串模式
            condition:
                $s  // 条件：如果找到 $s 模式
        }
    )";
    
    YRX_RULES* rules = nullptr;  // 规则指针，初始化为空
    YRX_RESULT result = yrx_compile(string_rule, &rules);  // 编译规则
    TEST_ASSERT(result == YRX_SUCCESS, "Compile string pattern rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        result = yrx_scanner_create(rules, &scanner);  // 创建扫描器
        TEST_ASSERT(result == YRX_SUCCESS, "Create scanner for string pattern");
        
        if (scanner) {
            std::string data = "Hello World";  // 要扫描的数据
            result = yrx_scanner_scan(scanner, 
                                     reinterpret_cast<const uint8_t*>(data.c_str()), 
                                     data.size());  // 扫描数据
            TEST_ASSERT(result == YRX_SUCCESS, "String pattern matching");
            
            yrx_scanner_destroy(scanner);  // 销毁扫描器
        }
        
        yrx_rules_destroy(rules);  // 销毁规则
    }
    
    // 测试十六进制模式
    // ... 类似实现
    
    // 测试正则表达式模式
    // ... 类似实现
}
```
- **说明**：测试各种模式匹配功能
- **验证点**：
  - 规则编译成功
  - 扫描器创建成功
  - 模式匹配成功

### 4. 元数据处理测试实现

```cpp
void test_metadata_handling() {
    std::cout << "\n=== Test: Metadata Handling ===" << std::endl;
    
    const char* rule_with_metadata = R"(
        rule test_metadata {
            meta:
                author = "test"  // 字符串元数据
                version = 1       // 整数元数据
                enabled = true    // 布尔元数据
                score = 9.5       // 浮点数元数据
            condition:
                true  // 条件：总是匹配
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_with_metadata, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule with metadata");
    
    if (rules) {
        // 测试元数据
        // ... 实现细节
        
        yrx_rules_destroy(rules);
    }
}
```
- **说明**：测试元数据处理功能
- **验证点**：
  - 规则编译成功
  - 元数据计数正确
  - 元数据类型正确
  - 元数据值正确

## YARA-X CAPI 核心函数说明

### 编译相关函数
- **yrx_compile**：编译 YARA 规则字符串，返回编译后的规则对象
- **yrx_compiler_create**：创建编译器对象
- **yrx_compiler_add_source**：向编译器添加规则源代码
- **yrx_compiler_build**：构建编译后的规则对象
- **yrx_compiler_destroy**：销毁编译器对象

### 扫描相关函数
- **yrx_scanner_create**：从规则创建扫描器
- **yrx_scanner_scan**：扫描数据缓冲区
- **yrx_scanner_on_matching_rule**：设置匹配规则的回调函数
- **yrx_scanner_destroy**：销毁扫描器

### 规则相关函数
- **yrx_rules_count**：获取规则数量
- **yrx_rules_destroy**：销毁规则对象
- **yrx_rule_identifier**：获取规则名称
- **yrx_rule_iter_tags**：迭代规则的标签
- **yrx_rule_iter_metadata**：迭代规则的元数据

### 全局变量相关函数
- **yrx_compiler_define_global_bool**：定义布尔类型全局变量
- **yrx_compiler_define_global_int**：定义整数类型全局变量
- **yrx_compiler_define_global_float**：定义浮点类型全局变量
- **yrx_compiler_define_global_string**：定义字符串类型全局变量
- **yrx_scanner_set_global_int**：设置扫描器级别的整数全局变量

## 测试执行流程

1. **编译测试模块**：使用 `make` 命令编译所有测试模块
2. **运行测试**：执行 `./bin/test_functionality` 运行功能验证测试
3. **测试执行**：测试模块按顺序执行以下测试：
   - 模式匹配测试
   - 元数据处理测试
   - 全局变量测试
   - 规则标签测试
   - 命名空间测试
4. **结果输出**：输出测试结果，包括通过和失败的测试用例数量

## 技术要点

1. **功能验证**：全面测试库的核心功能
2. **回调机制**：使用回调函数收集标签和规则信息
3. **资源管理**：确保在测试过程中正确管理资源
4. **测试覆盖**：覆盖多种功能场景，包括模式匹配、元数据处理等

## 测试结果

功能验证测试运行结果：
- 模式匹配测试：通过
- 元数据处理测试：通过
- 全局变量测试：通过
- 规则标签测试：通过
- 命名空间测试：通过

## 如何在自己的项目中使用

1. **包含头文件**：
   ```cpp
   #include "yara_x.h"
   ```

2. **编译规则**：
   ```cpp
   YRX_RULES* rules = nullptr;
   YRX_RESULT result = yrx_compile(rule_content, &rules);
   ```

3. **创建扫描器**：
   ```cpp
   YRX_SCANNER* scanner = nullptr;
   result = yrx_scanner_create(rules, &scanner);
   ```

4. **设置回调**：
   ```cpp
   yrx_scanner_on_matching_rule(scanner, rule_callback, &matched_rules);
   ```

5. **执行扫描**：
   ```cpp
   result = yrx_scanner_scan(scanner, data, data_size);
   ```

6. **处理元数据**：
   ```cpp
   // 迭代规则的元数据
   yrx_rule_iter_metadata(rule, metadata_callback, &metadata);
   ```

7. **使用全局变量**：
   ```cpp
   // 定义全局变量
   yrx_compiler_define_global_string(compiler, "my_string", "value");
   
   // 在扫描器级别修改全局变量
   yrx_scanner_set_global_int(scanner, "my_int", 42);
   ```

8. **清理资源**：
   ```cpp
   yrx_scanner_destroy(scanner);
   yrx_rules_destroy(rules);
   ```

## 总结

`test_functionality.cpp` 提供了一个全面的功能验证测试框架，验证了 YARA-X CAPI 库的核心功能。通过测试模式匹配、元数据处理、全局变量管理、规则标签和命名空间等功能，确保库的基本功能正常工作。

该测试模块不仅验证了库的基本功能，还测试了库在各种使用场景下的行为，为库的使用者提供了信心。对于不熟悉 C++ 和 YARA-X 的用户，这个测试模块也提供了一个很好的学习示例，展示了如何使用 YARA-X CAPI 库的核心功能。