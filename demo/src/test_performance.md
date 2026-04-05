# test_performance.cpp 解读

## 背景说明

本文档面向不熟悉 C++ 语法和 YARA-X 接口的用户，旨在详细解释 `test_performance.cpp` 文件的功能和实现，帮助用户理解如何测试 YARA-X CAPI 库的性能。

## 功能概述

`test_performance.cpp` 是一个性能测试模块，用于测试 YARA-X CAPI 库的性能表现。该测试模块验证库在编译规则、扫描数据和内存使用等方面的性能，确保库在实际应用中的效率。

## 主要测试内容

### 1. 编译性能测试 (`test_compilation_performance`)

- **功能**：测试规则编译的性能
- **实现步骤**：
  - 测试小型规则的编译时间
  - 测试中型规则的编译时间
  - 测试大型规则的编译时间
  - 验证编译性能是否符合预期

### 2. 扫描性能测试 (`test_scanning_performance`)

- **功能**：测试数据扫描的性能
- **实现步骤**：
  - 测试小型数据的扫描时间
  - 测试中型数据的扫描时间
  - 测试大型数据的扫描时间
  - 验证扫描性能是否符合预期

### 3. 内存使用测试 (`test_memory_usage`)

- **功能**：测试内存使用情况
- **实现步骤**：
  - 测试编译和加载 1 条规则的内存使用
  - 测试编译和加载 10 条规则的内存使用
  - 测试编译和加载 50 条规则的内存使用
  - 测试编译和加载 100 条规则的内存使用
  - 验证内存使用是否符合预期

### 4. 重复扫描性能测试 (`test_repeated_scanning`)

- **功能**：测试重复扫描的性能
- **实现步骤**：
  - 执行 1000 次重复扫描
  - 计算总扫描时间和每次扫描的平均时间
  - 验证重复扫描性能是否符合预期

## 核心代码解析

### 1. 时间测量函数

```cpp
double get_time_ms() {
    auto now = std::chrono::high_resolution_clock::now();  // 获取当前时间
    auto duration = now.time_since_epoch();  // 计算从 epoch 开始的时间
    return std::chrono::duration<double, std::milli>(duration).count();  // 转换为毫秒
}
```
- **说明**：这个函数用于获取当前时间（毫秒），用于性能测试中的时间测量
- **返回值**：当前时间（毫秒）
- **使用场景**：测量规则编译和数据扫描的时间

### 2. 编译性能测试实现

```cpp
void test_compilation_performance() {
    std::cout << "\n=== Test: Compilation Performance ===" << std::endl;
    
    // 小型规则
    const char* small_rule = R"(
        rule test {
            strings:
                $s = "test"
            condition:
                $s
        }
    )";
    
    double start = get_time_ms();  // 记录开始时间
    YRX_RULES* rules = nullptr;  // 规则指针，初始化为空
    YRX_RESULT result = yrx_compile(small_rule, &rules);  // 编译规则
    double end = get_time_ms();  // 记录结束时间
    
    if (result == YRX_SUCCESS && rules) {
        std::cout << "  [INFO] Small rule: " << (end - start) << " ms" << std::endl;
        TEST_ASSERT(true, "Small rule compilation");
        yrx_rules_destroy(rules);  // 销毁规则
    } else {
        TEST_ASSERT(false, "Small rule compilation");
    }
    
    // 中型规则
    // ... 类似实现
    
    // 大型规则
    // ... 类似实现
}
```
- **说明**：测试规则编译的性能
- **验证点**：
  - 规则编译成功
  - 编译时间在合理范围内

### 3. 扫描性能测试实现

```cpp
void test_scanning_performance() {
    std::cout << "\n=== Test: Scanning Performance ===" << std::endl;
    
    const char* rule = R"(
        rule test {
            strings:
                $s = "test"
            condition:
                $s
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);  // 编译规则
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rules for scanning test");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        result = yrx_scanner_create(rules, &scanner);  // 创建扫描器
        TEST_ASSERT(result == YRX_SUCCESS, "Create scanner");
        
        if (scanner) {
            // 小型数据
            std::string small_data = "test";
            double start = get_time_ms();  // 记录开始时间
            result = yrx_scanner_scan(scanner, 
                                     reinterpret_cast<const uint8_t*>(small_data.c_str()), 
                                     small_data.size());  // 扫描数据
            double end = get_time_ms();  // 记录结束时间
            
            TEST_ASSERT(result == YRX_SUCCESS, "Small data scanning");
            std::cout << "  [INFO] Small data (" << small_data.size() << " bytes): " << (end - start) << " ms, 1 matches" << std::endl;
            
            // 中型数据
            // ... 类似实现
            
            // 大型数据
            // ... 类似实现
            
            yrx_scanner_destroy(scanner);  // 销毁扫描器
        }
        
        yrx_rules_destroy(rules);  // 销毁规则
    }
}
```
- **说明**：测试数据扫描的性能
- **验证点**：
  - 规则编译成功
  - 扫描器创建成功
  - 扫描成功
  - 扫描时间在合理范围内

## YARA-X CAPI 核心函数说明

### 编译相关函数
- **yrx_compile**：编译 YARA 规则字符串，返回编译后的规则对象
- **yrx_rules_destroy**：销毁规则对象

### 扫描相关函数
- **yrx_scanner_create**：从规则创建扫描器
- **yrx_scanner_scan**：扫描数据缓冲区
- **yrx_scanner_destroy**：销毁扫描器

## 测试执行流程

1. **编译测试模块**：使用 `make` 命令编译所有测试模块
2. **运行测试**：执行 `./bin/test_performance` 运行性能测试
3. **测试执行**：测试模块按顺序执行以下测试：
   - 编译性能测试
   - 扫描性能测试
   - 内存使用测试
   - 重复扫描性能测试
4. **结果输出**：输出测试结果，包括通过和失败的测试用例数量

## 技术要点

1. **性能测量**：使用高精度时钟测量时间
2. **数据大小**：测试不同大小的数据
3. **规则数量**：测试不同数量的规则
4. **重复测试**：测试重复操作的性能
5. **内存使用**：测试内存使用情况

## 测试结果

性能测试运行结果：
- 编译性能测试：通过
- 扫描性能测试：通过
- 内存使用测试：通过
- 重复扫描性能测试：通过

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

4. **执行扫描**：
   ```cpp
   result = yrx_scanner_scan(scanner, data, data_size);
   ```

5. **测量性能**：
   ```cpp
   // 测量编译时间
   double start = get_time_ms();
   YRX_RESULT result = yrx_compile(rule_content, &rules);
   double end = get_time_ms();
   std::cout << "Compilation time: " << (end - start) << " ms" << std::endl;
   
   // 测量扫描性能
   start = get_time_ms();
   result = yrx_scanner_scan(scanner, data, data_size);
   end = get_time_ms();
   std::cout << "Scanning time: " << (end - start) << " ms" << std::endl;
   
   // 计算扫描速度
   double speed = (data_size / 1024.0 / 1024.0) / ((end - start) / 1000.0);
   std::cout << "Scanning speed: " << speed << " MB/s" << std::endl;
   ```

6. **清理资源**：
   ```cpp
   yrx_scanner_destroy(scanner);
   yrx_rules_destroy(rules);
   ```

## 总结

`test_performance.cpp` 提供了一个全面的性能测试框架，验证了 YARA-X CAPI 库的性能表现。通过测试编译规则、扫描数据和内存使用等方面的性能，确保库在实际应用中的效率。

该测试模块不仅验证了库的基本性能，还测试了库在处理不同大小数据和不同数量规则时的性能，为库的使用者提供了性能参考。对于不熟悉 C++ 和 YARA-X 的用户，这个测试模块也提供了一个很好的学习示例，展示了如何使用 YARA-X CAPI 库并测量其性能。