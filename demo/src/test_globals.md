# test_globals.cpp 代码解读

本文档详细解读 `test_globals.cpp` 文件，测试 YARA-X CAPI 的全局变量功能。

## 文件概述

这个文件包含 10 个测试函数，验证：
- 编译器级别定义全局变量（bool、int、float、string、JSON）
- 扫描器级别设置全局变量
- 多个全局变量组合使用

---

## 1. 辅助结构体和函数

```cpp
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
```

---

## 2. 全局变量概念

### 什么是全局变量？

全局变量是在 YARA 规则外部定义的变量，可以在规则条件中使用。这使得规则更加灵活，可以在运行时动态改变行为。

### 两种定义方式

| 方式 | 函数 | 作用时机 | 灵活性 |
|------|------|----------|--------|
| 编译器级别 | `yrx_compiler_define_global_*` | 编译时 | 固定值 |
| 扫描器级别 | `yrx_scanner_set_global_*` | 扫描时 | 可动态修改 |

---

## 3. test_global_bool - 布尔全局变量

```cpp
void test_global_bool() {
    std::cout << "\n=== Test: Global Boolean Variable ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler");
    
    if (result == YRX_SUCCESS) {
        result = yrx_compiler_define_global_bool(compiler, "my_bool", true);
        TEST_ASSERT(result == YRX_SUCCESS, "Define global bool");
        
        result = yrx_compiler_add_source(compiler, R"(
            rule bool_test {
                condition:
                    my_bool
            }
        )");
        TEST_ASSERT(result == YRX_SUCCESS, "Add source with global bool");
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        TEST_ASSERT(rules != nullptr, "Build rules");
        
        if (rules) {
            ScanResult scan_result = {0, {}};
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
            yrx_scanner_destroy(scanner);
            
            TEST_ASSERT(scan_result.match_count == 1, "Match with bool=true");
            
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_define_global_bool(compiler, "变量名", 值);
```

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| compiler | `YRX_COMPILER*` | 编译器指针 |
| name | `const char*` | 变量名称 |
| value | `bool` | 布尔值（true/false） |

**YARA 规则中使用**：

```yara
rule bool_test {
    condition:
        my_bool    // 直接使用变量名
}
```

---

## 4. test_global_int - 整数全局变量

```cpp
void test_global_int() {
    // ...
    result = yrx_compiler_define_global_int(compiler, "my_int", 100);
    // ...
    result = yrx_compiler_add_source(compiler, R"(
        rule int_test {
            condition:
                my_int > 50
        }
    )");
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_define_global_int(compiler, "变量名", 值);
```

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| compiler | `YRX_COMPILER*` | 编译器指针 |
| name | `const char*` | 变量名称 |
| value | `int64_t` | 64 位整数 |

**YARA 规则中使用**：

```yara
rule int_test {
    condition:
        my_int > 50      // 比较运算
        my_int == 100    // 相等判断
        my_int >= 0      // 范围检查
}
```

---

## 5. test_global_float - 浮点数全局变量

```cpp
void test_global_float() {
    // ...
    result = yrx_compiler_define_global_float(compiler, "my_float", 3.14159);
    // ...
    result = yrx_compiler_add_source(compiler, R"(
        rule float_test {
            condition:
                my_float > 3.0 and my_float < 4.0
        }
    )");
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_define_global_float(compiler, "变量名", 值);
```

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| compiler | `YRX_COMPILER*` | 编译器指针 |
| name | `const char*` | 变量名称 |
| value | `double` | 64 位浮点数 |

**注意事项**：
- 浮点数比较建议使用范围而非精确相等
- 避免直接使用 `==` 比较浮点数

---

## 6. test_global_string - 字符串全局变量

```cpp
void test_global_string() {
    // ...
    result = yrx_compiler_define_global_str(compiler, "my_str", "expected_value");
    // ...
    result = yrx_compiler_add_source(compiler, R"(
        rule string_test {
            condition:
                my_str == "expected_value"
        }
    )");
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_define_global_str(compiler, "变量名", "字符串值");
```

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| compiler | `YRX_COMPILER*` | 编译器指针 |
| name | `const char*` | 变量名称 |
| value | `const char*` | 字符串值 |

**YARA 规则中使用**：

```yara
rule string_test {
    condition:
        my_str == "expected_value"    // 字符串相等
        my_str contains "partial"     // 包含检查
}
```

---

## 7. test_scanner_set_global_bool - 扫描器设置布尔变量

```cpp
void test_scanner_set_global_bool() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    // 编译时定义默认值 false
    yrx_compiler_define_global_bool(compiler, "my_flag", false);
    yrx_compiler_add_source(compiler, R"(
        rule flag_test {
            condition:
                my_flag
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        // 第一次扫描：使用默认值 false，不匹配
        ScanResult result1 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result1);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result1.match_count == 0, "No match with default false");
        
        // 扫描器级别修改变量为 true
        YRX_RESULT set_result = yrx_scanner_set_global_bool(scanner, "my_flag", true);
        TEST_ASSERT(set_result == YRX_SUCCESS, "Set global bool to true");
        
        // 第二次扫描：使用修改后的值 true，匹配
        ScanResult result2 = {0, {}};
        yrx_scanner_on_matching_rule(scanner, rule_callback, &result2);
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result2.match_count == 1, "Match after setting to true");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**扫描器级别修改变量**：

```cpp
yrx_scanner_set_global_bool(scanner, "变量名", 新值);
```

**使用场景**：

| 场景 | 说明 |
|------|------|
| 条件开关 | 根据不同扫描需求启用/禁用某些规则 |
| 环境差异 | 不同环境使用不同的配置值 |
| 动态阈值 | 根据扫描上下文调整阈值 |

**流程图**：

```
编译时定义默认值 (false)
        ↓
创建扫描器
        ↓
第一次扫描 → 不匹配（变量为 false）
        ↓
扫描器修改变量 (true)
        ↓
第二次扫描 → 匹配（变量为 true）
```

---

## 8. test_scanner_set_global_int - 扫描器设置整数变量

```cpp
void test_scanner_set_global_int() {
    // ...
    yrx_compiler_define_global_int(compiler, "threshold", 100);
    // ...
    // 第一次扫描：threshold=100，条件 threshold > 150 不满足
    TEST_ASSERT(result1.match_count == 0, "No match with threshold=100");
    
    // 修改为 200
    yrx_scanner_set_global_int(scanner, "threshold", 200);
    
    // 第二次扫描：threshold=200，条件 threshold > 150 满足
    TEST_ASSERT(result2.match_count == 1, "Match with threshold=200");
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_scanner_set_global_int(scanner, "变量名", 新值);
```

**典型应用**：

```yara
rule file_size_check {
    condition:
        filesize > threshold
}
```

- 可以根据不同扫描场景设置不同的文件大小阈值
- 小文件扫描设置较小阈值
- 大文件扫描设置较大阈值

---

## 9. test_scanner_set_global_string - 扫描器设置字符串变量

```cpp
void test_scanner_set_global_string() {
    // ...
    yrx_compiler_define_global_str(compiler, "target", "default");
    // ...
    yrx_scanner_set_global_string(scanner, "target", "custom_value");
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_scanner_set_global_string(scanner, "变量名", "新字符串");
```

**典型应用**：

```yara
rule target_match {
    strings:
        $target = "placeholder"
    condition:
        $target
}
```

- 可以动态指定要匹配的目标字符串
- 不同扫描任务匹配不同的目标

---

## 10. test_scanner_set_global_float - 扫描器设置浮点变量

```cpp
void test_scanner_set_global_float() {
    // ...
    yrx_compiler_define_global_float(compiler, "ratio", 1.0);
    // ...
    yrx_scanner_set_global_float(scanner, "ratio", 3.0);
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_scanner_set_global_float(scanner, "变量名", 新值);
```

---

## 11. test_multiple_global_vars - 多个全局变量

```cpp
void test_multiple_global_vars() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_define_global_bool(compiler, "enabled", true);
    yrx_compiler_define_global_int(compiler, "count", 10);
    yrx_compiler_define_global_str(compiler, "name", "test");
    
    yrx_compiler_add_source(compiler, R"(
        rule multi_global {
            condition:
                enabled and count > 5 and name == "test"
        }
    )");
    
    // ...
}
```

### 解读

**组合使用多个变量**：

```yara
rule multi_global {
    condition:
        enabled and count > 5 and name == "test"
}
```

- 可以在条件中组合使用多个全局变量
- 支持逻辑运算符：`and`、`or`、`not`

---

## 12. test_global_json - JSON 全局变量

```cpp
void test_global_json() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* json_value = R"({"key": "value", "number": 42})";
    YRX_RESULT result = yrx_compiler_define_global_json(compiler, "my_json", json_value);
    TEST_ASSERT(result == YRX_SUCCESS, "Define global JSON");
    
    yrx_compiler_add_source(compiler, R"(
        rule json_test {
            condition:
                true
        }
    )");
    
    // ...
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_define_global_json(compiler, "变量名", "JSON字符串");
```

**JSON 变量用途**：
- 传递复杂结构化数据
- 配置信息
- 多字段参数

**JSON 格式示例**：

```json
{
    "author": "security_team",
    "severity": "high",
    "version": 2,
    "enabled": true
}
```

---

## 13. API 函数总结

### 编译器级别定义

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_compiler_define_global_bool` | compiler, name, value | 定义布尔全局变量 |
| `yrx_compiler_define_global_int` | compiler, name, value | 定义整数全局变量 |
| `yrx_compiler_define_global_float` | compiler, name, value | 定义浮点全局变量 |
| `yrx_compiler_define_global_str` | compiler, name, value | 定义字符串全局变量 |
| `yrx_compiler_define_global_json` | compiler, name, json_str | 定义 JSON 全局变量 |

### 扫描器级别修改

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_scanner_set_global_bool` | scanner, name, value | 修改布尔全局变量 |
| `yrx_scanner_set_global_int` | scanner, name, value | 修改整数全局变量 |
| `yrx_scanner_set_global_float` | scanner, name, value | 修改浮点全局变量 |
| `yrx_scanner_set_global_string` | scanner, name, value | 修改字符串全局变量 |

---

## 14. 使用场景

### 场景 1：动态阈值

```cpp
// 编译时定义默认阈值
yrx_compiler_define_global_int(compiler, "size_threshold", 1024);

// 扫描时根据文件类型调整
if (is_large_file) {
    yrx_scanner_set_global_int(scanner, "size_threshold", 1048576);
}
```

```yara
rule check_size {
    condition:
        filesize > size_threshold
}
```

### 场景 2：条件开关

```cpp
// 编译时定义开关
yrx_compiler_define_global_bool(compiler, "check_pe", true);
yrx_compiler_define_global_bool(compiler, "check_elf", false);

// 扫描时根据需要开启
if (target_os == "linux") {
    yrx_scanner_set_global_bool(scanner, "check_elf", true);
    yrx_scanner_set_global_bool(scanner, "check_pe", false);
}
```

```yara
rule pe_check {
    condition:
        check_pe and uint16(0) == 0x5A4D
}

rule elf_check {
    condition:
        check_elf and uint32(0) == 0x464C457F
}
```

### 场景 3：目标字符串

```cpp
// 动态指定要检测的字符串
yrx_scanner_set_global_string(scanner, "target_string", malware_signature);
```

```yara
rule target_match {
    strings:
        $target = /target_string/  // 使用变量
    condition:
        $target
}
```

---

## 15. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    全局变量使用流程                          │
├─────────────────────────────────────────────────────────────┤
│  1. 创建编译器                                              │
│           ↓                                                 │
│  2. 定义全局变量（编译器级别，设置默认值）                  │
│           ↓                                                 │
│  3. 添加使用全局变量的规则源代码                            │
│           ↓                                                 │
│  4. 构建规则                                                │
│           ↓                                                 │
│  5. 销毁编译器                                              │
│           ↓                                                 │
│  6. 创建扫描器                                              │
│           ↓                                                 │
│  7. [可选] 修改全局变量（扫描器级别）                       │
│           ↓                                                 │
│  8. 执行扫描                                                │
│           ↓                                                 │
│  9. 销毁扫描器和规则                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 16. 注意事项

1. **变量必须先定义后使用**：
   - 在添加源代码之前定义变量
   - 否则编译会报"未知标识符"错误

2. **类型匹配**：
   - 定义类型和使用类型必须一致
   - 不能将整数变量当字符串使用

3. **扫描器修改的作用域**：
   - 扫描器级别的修改只影响该扫描器
   - 不影响其他扫描器或重新创建的扫描器

4. **变量命名**：
   - 使用有效的标识符名称
   - 避免与 YARA 关键字冲突
