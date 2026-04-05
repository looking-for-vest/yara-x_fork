# test_error_handling.cpp 代码解读

本文档详细解读 `test_error_handling.cpp` 文件，测试 YARA-X CAPI 的错误处理功能。

## 文件概述

这个文件包含 15 个测试函数，验证：
- 语法错误处理
- 无效参数处理
- 变量错误处理
- 错误信息获取
- 警告信息获取
- 超时处理

---

## 1. 错误类型概述

### YRX_RESULT 枚举

| 错误码 | 说明 |
|--------|------|
| `YRX_SUCCESS` | 操作成功 |
| `YRX_SYNTAX_ERROR` | 语法错误 |
| `YRX_INVALID_ARGUMENT` | 无效参数 |
| `YRX_VARIABLE_ERROR` | 变量错误 |
| `YRX_TIMEOUT` | 超时 |
| `YRX_IO_ERROR` | I/O 错误 |

---

## 2. test_syntax_error - 语法错误

```cpp
void test_syntax_error() {
    std::cout << "\n=== Test: Syntax Error ===" << std::endl;
    
    const char* invalid_rule = R"(
        rule invalid {
            strings:
                $a = "test
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(invalid_rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Syntax error detected");
    TEST_ASSERT(rules == nullptr, "Rules is null on syntax error");
    
    const char* error = yrx_last_error();
    TEST_ASSERT(error != nullptr, "Error message is not null");
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}
```

### 解读

**错误示例**：
```yara
$a = "test    // 缺少闭合引号
```

**错误处理模式**：
1. 检查返回值是否为错误码
2. 检查输出参数是否为 nullptr
3. 使用 `yrx_last_error()` 获取详细错误信息

---

## 3. test_unknown_identifier - 未知标识符

```cpp
void test_unknown_identifier() {
    const char* rule = R"(
        rule unknown_id {
            condition:
                undefined_var
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Unknown identifier error");
    
    const char* error = yrx_last_error();
    std::cout << "    Error message: " << (error ? error : "(null)") << std::endl;
}
```

### 解读

**错误示例**：
```yara
condition:
    undefined_var    // 使用了未定义的变量
```

**常见未知标识符错误**：
| 情况 | 示例 |
|------|------|
| 未定义变量 | `undefined_var` |
| 拼写错误 | `$a` 写成 `$b` |
| 未声明的全局变量 | 直接使用未定义的全局变量 |

---

## 4. test_invalid_regex - 无效正则表达式

```cpp
void test_invalid_regex() {
    const char* rule = R"(
        rule bad_regex {
            strings:
                $re = /unclosed[/
            condition:
                $re
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Invalid regex error");
}
```

### 解读

**错误示例**：
```yara
$re = /unclosed[/    // 字符类未闭合
```

**常见正则错误**：
| 错误类型 | 示例 |
|----------|------|
| 未闭合括号 | `/unclosed[/` |
| 无效转义 | `/\x` |
| 无效量词 | `/a**/` |
| 未闭合分组 | `/(abc/` |

---

## 5. test_invalid_hex_pattern - 无效十六进制模式

```cpp
void test_invalid_hex_pattern() {
    const char* rule = R"(
        rule bad_hex {
            strings:
                $hex = { GG HH }
            condition:
                $hex
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Invalid hex pattern error");
}
```

### 解读

**错误示例**：
```yara
$hex = { GG HH }    // G 和 H 不是有效的十六进制字符
```

**有效的十六进制字符**：
- 数字：`0-9`
- 字母：`A-F` 或 `a-f`
- 通配符：`?`

---

## 6. test_duplicate_rule_name - 重复规则名

```cpp
void test_duplicate_rule_name() {
    const char* rule = R"(
        rule duplicate { condition: true }
        rule duplicate { condition: false }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    
    TEST_ASSERT(result == YRX_SYNTAX_ERROR, "Duplicate rule name error");
}
```

### 解读

**错误示例**：
```yara
rule duplicate { condition: true }
rule duplicate { condition: false }  // 同名规则
```

**解决方案**：
- 使用不同的规则名
- 使用命名空间隔离同名规则

---

## 7. test_invalid_argument_null_compiler - 空编译器参数

```cpp
void test_invalid_argument_null_compiler() {
    YRX_RESULT result = yrx_compiler_add_source(nullptr, "rule test { condition: true }");
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null compiler returns INVALID_ARGUMENT");
}
```

### 解读

**YRX_INVALID_ARGUMENT 错误**：
- 当传入空指针（nullptr）时返回
- 表示参数无效

**常见触发场景**：
| 函数 | 无效参数 |
|------|----------|
| `yrx_compiler_add_source` | compiler = nullptr |
| `yrx_scanner_create` | rules = nullptr |
| `yrx_scanner_scan` | scanner = nullptr |

---

## 8. test_invalid_argument_null_rules - 空规则参数

```cpp
void test_invalid_argument_null_rules() {
    YRX_SCANNER* scanner = nullptr;
    YRX_RESULT result = yrx_scanner_create(nullptr, &scanner);
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null rules returns INVALID_ARGUMENT");
}
```

---

## 9. test_invalid_argument_null_scanner - 空扫描器参数

```cpp
void test_invalid_argument_null_scanner() {
    const char* data = "test";
    YRX_RESULT result = yrx_scanner_scan(nullptr, reinterpret_cast<const uint8_t*>(data), strlen(data));
    
    TEST_ASSERT(result == YRX_INVALID_ARGUMENT, "Null scanner returns INVALID_ARGUMENT");
}
```

---

## 10. test_variable_error_undefined - 未定义变量错误

```cpp
void test_variable_error_undefined() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    YRX_RESULT add_result = yrx_compiler_add_source(compiler, R"(
        rule use_var {
            condition:
                my_var > 0
        }
    )");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    
    TEST_ASSERT(rules == nullptr || add_result == YRX_SYNTAX_ERROR, "Build fails with undefined variable");
    
    const char* error = yrx_last_error();
    TEST_ASSERT(error != nullptr, "Error message is set");
    
    if (rules) {
        yrx_rules_destroy(rules);
    }
    yrx_compiler_destroy(compiler);
}
```

### 解读

**正确用法**：
```cpp
// 先定义变量
yrx_compiler_define_global_int(compiler, "my_var", 100);

// 再使用变量
yrx_compiler_add_source(compiler, R"(
    rule use_var {
        condition:
            my_var > 0
    }
)");
```

---

## 11. test_variable_error_wrong_type - 变量类型错误

```cpp
void test_variable_error_wrong_type() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    YRX_RESULT result = yrx_compiler_define_global_int(compiler, "my_int", 100);
    TEST_ASSERT(result == YRX_SUCCESS, "Define int variable");
    
    result = yrx_compiler_define_global_str(compiler, "my_int", "string");
    TEST_ASSERT(result == YRX_VARIABLE_ERROR, "Redefine with wrong type fails");
    
    yrx_compiler_destroy(compiler);
}
```

### 解读

**错误示例**：
```cpp
yrx_compiler_define_global_int(compiler, "my_var", 100);    // 定义为整数
yrx_compiler_define_global_str(compiler, "my_var", "text"); // 错误：重定义为字符串
```

**正确做法**：
- 变量一旦定义，类型不可更改
- 使用不同的变量名

---

## 12. test_compiler_errors_json - 获取错误 JSON

```cpp
void test_compiler_errors_json() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, R"(
        rule error_test {
            condition:
                undefined_identifier
        }
    )");
    
    YRX_BUFFER* buffer = nullptr;
    YRX_RESULT result = yrx_compiler_errors_json(compiler, &buffer);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Get errors as JSON");
    
    if (buffer && buffer->data) {
        std::string json(reinterpret_cast<char*>(buffer->data), buffer->length);
        std::cout << "    Errors JSON: " << json.substr(0, 200) << "..." << std::endl;
        
        TEST_ASSERT(json.find("undefined_identifier") != std::string::npos || 
                     json.find("UnknownIdentifier") != std::string::npos ||
                     json.find("undefined") != std::string::npos,
                     "JSON contains error info");
        
        yrx_buffer_destroy(buffer);
    }
    
    yrx_compiler_destroy(compiler);
}
```

### 解读

**API 函数**：

```cpp
yrx_compiler_errors_json(compiler, &buffer);
```

**返回 JSON 格式示例**：
```json
[
  {
    "type": "UnknownIdentifier",
    "message": "unknown identifier `undefined_identifier`",
    "code": "E009",
    "location": {
      "line": 4,
      "column": 17
    }
  }
]
```

**std::string::find**：
```cpp
json.find("keyword") != std::string::npos
```
- 在字符串中查找子串
- 返回位置索引，未找到返回 `std::string::npos`

---

## 13. test_compiler_warnings_json - 获取警告 JSON

```cpp
void test_compiler_warnings_json() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, R"(
        rule warning_test {
            strings:
                $a = "test"
            condition:
                true
        }
    )");
    
    YRX_BUFFER* buffer = nullptr;
    YRX_RESULT result = yrx_compiler_warnings_json(compiler, &buffer);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Get warnings as JSON");
    
    if (buffer && buffer->data) {
        std::string json(reinterpret_cast<char*>(buffer->data), buffer->length);
        std::cout << "    Warnings JSON length: " << json.length() << std::endl;
        yrx_buffer_destroy(buffer);
    }
    
    yrx_compiler_destroy(compiler);
}
```

### 解读

**警告示例**：
```yara
rule warning_test {
    strings:
        $a = "test"
    condition:
        true    // 警告：定义了 $a 但未使用
}
```

**常见警告**：
| 警告类型 | 说明 |
|----------|------|
| 未使用的字符串 | 定义了但未在条件中使用 |
| 永远为真/假 | 条件总是成立或不成立 |
| 冗余条件 | 条件可以简化 |

---

## 14. test_last_error_clears - 错误清除

```cpp
void test_last_error_clears() {
    YRX_RULES* rules = nullptr;
    yrx_compile("rule invalid { condition: undefined }", &rules);
    
    const char* error1 = yrx_last_error();
    TEST_ASSERT(error1 != nullptr, "Error is set after failure");
    
    YRX_RULES* good_rules = nullptr;
    YRX_RESULT result = yrx_compile("rule valid { condition: true }", &good_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Valid compile succeeds");
    
    const char* error2 = yrx_last_error();
    TEST_ASSERT(error2 == nullptr, "Error cleared after success");
    
    if (good_rules) {
        yrx_rules_destroy(good_rules);
    }
}
```

### 解读

**错误状态管理**：
- 错误信息是线程局部的
- 成功操作会清除之前的错误
- 失败操作会设置新的错误

---

## 15. test_empty_source - 空源码处理

```cpp
void test_empty_source() {
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile("", &rules);
    
    TEST_ASSERT(result == YRX_SUCCESS || result == YRX_SYNTAX_ERROR, "Empty source handled");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 0, "No rules compiled from empty source");
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**空源码行为**：
- 可能返回成功（0 条规则）
- 可能返回语法错误
- 规则数量为 0

---

## 16. test_scanner_timeout - 扫描超时

```cpp
void test_scanner_timeout() {
    const char* rule = R"(
        rule timeout_test {
            condition:
                true
        }
    )";
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile rule");
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        result = yrx_scanner_set_timeout(scanner, 1);
        TEST_ASSERT(result == YRX_SUCCESS, "Set timeout to 1 second");
        
        const char* data = "test data";
        result = yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        TEST_ASSERT(result == YRX_SUCCESS, "Scan completes within timeout");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**API 函数**：

```cpp
yrx_scanner_set_timeout(scanner, seconds);
```

**超时用途**：
- 防止恶意文件导致无限扫描
- 限制单个文件扫描时间
- 避免资源耗尽

**超时处理**：
```cpp
result = yrx_scanner_scan(scanner, data, len);
if (result == YRX_TIMEOUT) {
    // 处理超时情况
}
```

---

## 17. API 函数总结

### 错误处理相关

| 函数 | 作用 |
|------|------|
| `yrx_last_error` | 获取最近错误信息 |
| `yrx_compiler_errors_json` | 获取编译错误（JSON 格式） |
| `yrx_compiler_warnings_json` | 获取编译警告（JSON 格式） |

### 超时相关

| 函数 | 作用 |
|------|------|
| `yrx_scanner_set_timeout` | 设置扫描超时时间（秒） |

---

## 18. 错误处理最佳实践

### 检查返回值

```cpp
YRX_RESULT result = yrx_compile(rule, &rules);
if (result != YRX_SUCCESS) {
    const char* error = yrx_last_error();
    std::cerr << "Error: " << (error ? error : "Unknown error") << std::endl;
    return;
}
```

### 检查输出参数

```cpp
YRX_RULES* rules = nullptr;
yrx_compile(rule, &rules);
if (rules == nullptr) {
    // 编译失败
    return;
}
```

### 获取详细错误信息

```cpp
YRX_COMPILER* compiler = nullptr;
yrx_compiler_create(0, &compiler);

yrx_compiler_add_source(compiler, rule_source);

YRX_BUFFER* errors = nullptr;
yrx_compiler_errors_json(compiler, &errors);

// 解析 JSON 获取详细错误位置和类型
std::string json(reinterpret_cast<char*>(errors->data), errors->length);
// 处理 JSON...

yrx_buffer_destroy(errors);
```

### 资源清理

```cpp
YRX_RULES* rules = nullptr;
YRX_SCANNER* scanner = nullptr;

try {
    if (yrx_compile(rule, &rules) != YRX_SUCCESS) {
        throw std::runtime_error("Compile failed");
    }
    
    if (yrx_scanner_create(rules, &scanner) != YRX_SUCCESS) {
        throw std::runtime_error("Scanner create failed");
    }
    
    // 使用 scanner...
    
} catch (...) {
    // 异常处理
}

// 清理资源
if (scanner) yrx_scanner_destroy(scanner);
if (rules) yrx_rules_destroy(rules);
```

---

## 19. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    错误处理流程                              │
├─────────────────────────────────────────────────────────────┤
│  1. 调用 API 函数                                           │
│           ↓                                                 │
│  2. 检查返回值 (YRX_RESULT)                                 │
│           ↓                                                 │
│     ┌───────┴───────┐                                       │
│     ↓               ↓                                       │
│  YRX_SUCCESS    其他错误码                                  │
│     ↓               ↓                                       │
│  继续执行    yrx_last_error()                               │
│                   ↓                                         │
│              获取错误信息                                    │
│                   ↓                                         │
│              处理错误                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 20. 常见错误及解决方案

| 错误类型 | 原因 | 解决方案 |
|----------|------|----------|
| `YRX_SYNTAX_ERROR` | 规则语法错误 | 检查规则语法，修复错误 |
| `YRX_INVALID_ARGUMENT` | 传入空指针 | 检查参数是否有效 |
| `YRX_VARIABLE_ERROR` | 变量定义/使用错误 | 正确定义变量后再使用 |
| `YRX_TIMEOUT` | 扫描超时 | 增加超时时间或优化规则 |
| `YRX_IO_ERROR` | 文件读写错误 | 检查文件路径和权限 |
