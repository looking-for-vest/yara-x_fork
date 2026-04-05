# test_basic_compile.cpp 代码解读

本文档详细解读 `test_basic_compile.cpp` 文件，测试 YARA-X CAPI 的基本编译功能。

## 文件概述

这个文件包含 11 个测试函数，验证 YARA-X CAPI 的基础功能：
- 规则编译
- 编译器生命周期
- 多规则编译
- 命名空间
- 文件加载
- include 目录

---

## 1. 头文件引入

```cpp
#include <iostream>
#include <cassert>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "yara_x.h"
}
```

### 解读

| 头文件 | 用途 |
|--------|------|
| `<iostream>` | 标准输入输出流 |
| `<cassert>` | C 风格断言宏 `assert()` |
| `<cstring>` | C 字符串操作函数 |
| `<fstream>` | 文件输入输出流，用于读取规则文件 |
| `<sstream>` | 字符串流，用于读取文件内容 |
| `<string>` | C++ 字符串类 |
| `<vector>` | 动态数组容器 |

---

## 2. 测试框架

```cpp
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
```

### 解读

**静态变量**：
- `static` 关键字表示变量只在当前文件可见
- `tests_passed`：通过的测试数量
- `tests_failed`：失败的测试数量

**宏定义说明**：

```cpp
#define TEST_ASSERT(cond, msg)
```

- `#define`：预处理器指令，定义宏
- `cond`：测试条件
- `msg`：测试描述信息

**do-while(0) 模式**：
```cpp
do { ... } while(0)
```
- 这是一个常见的宏定义技巧
- 确保宏在使用时像普通语句一样工作
- 可以安全地在 if-else 语句中使用

**使用示例**：
```cpp
TEST_ASSERT(result == YRX_SUCCESS, "Compile simple rule");
// 如果 result == YRX_SUCCESS，打印 [PASS] Compile simple rule
// 否则打印 [FAIL] Compile simple rule
```

---

## 3. test_simple_compile - 简单编译测试

```cpp
void test_simple_compile() {
    std::cout << "\n=== Test: Simple Compile ===" << std::endl;
    
    const char* rule = "rule test { condition: true }";
    YRX_RULES* rules = nullptr;
    
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile simple rule");
    TEST_ASSERT(rules != nullptr, "Rules object is not null");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 1, "Rule count is 1");
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**API 函数**：

| 函数 | 参数 | 返回值 | 作用 |
|------|------|--------|------|
| `yrx_compile` | source, &rules | YRX_RESULT | 一步完成编译 |
| `yrx_rules_count` | rules | int | 获取规则数量 |
| `yrx_rules_destroy` | rules | void | 销毁规则对象 |

**流程**：
```
定义规则字符串 → 调用 yrx_compile → 检查结果 → 获取规则数量 → 销毁规则
```

**`yrx_compile` vs 编译器流程**：

| 方式 | 步骤 | 适用场景 |
|------|------|----------|
| `yrx_compile` | 一步完成 | 简单的单文件编译 |
| 编译器流程 | 创建→添加→构建 | 需要多文件、命名空间等 |

---

## 4. test_compiler_create_destroy - 编译器生命周期

```cpp
void test_compiler_create_destroy() {
    std::cout << "\n=== Test: Compiler Create/Destroy ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(0, &compiler);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Compiler created successfully");
    TEST_ASSERT(compiler != nullptr, "Compiler is not null");
    
    if (compiler) {
        yrx_compiler_destroy(compiler);
        std::cout << "  [INFO] Compiler destroyed" << std::endl;
    }
}
```

### 解读

**编译器创建**：
```cpp
YRX_RESULT result = yrx_compiler_create(0, &compiler);
```
- 第一个参数 `0` 是编译器标志（flags）
- 第二个参数是输出参数，返回创建的编译器指针

**编译器标志**：
| 标志 | 值 | 作用 |
|------|-----|------|
| 默认 | 0 | 无特殊选项 |
| `YRX_COLORIZE_ERRORS` | - | 错误信息着色 |
| `YRX_RELAXED_RE_SYNTAX` | - | 宽松的正则语法 |
| `YRX_ENABLE_CONDITION_OPTIMIZATION` | - | 启用条件优化 |

---

## 5. test_compiler_add_source - 添加多个源

```cpp
void test_compiler_add_source() {
    std::cout << "\n=== Test: Compiler Add Source ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* rule1 = "rule rule1 { condition: true }";
    const char* rule2 = "rule rule2 { condition: false }";
    
    YRX_RESULT result1 = yrx_compiler_add_source(compiler, rule1);
    TEST_ASSERT(result1 == YRX_SUCCESS, "Add first rule");
    
    YRX_RESULT result2 = yrx_compiler_add_source(compiler, rule2);
    TEST_ASSERT(result2 == YRX_SUCCESS, "Add second rule");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    TEST_ASSERT(rules != nullptr, "Build rules successfully");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 2, "Rule count is 2");
        yrx_rules_destroy(rules);
    }
    
    yrx_compiler_destroy(compiler);
}
```

### 解读

**多源编译流程**：

```
创建编译器
    ↓
添加第一个源 → yrx_compiler_add_source(compiler, rule1)
    ↓
添加第二个源 → yrx_compiler_add_source(compiler, rule2)
    ↓
构建规则 → yrx_compiler_build(compiler)
    ↓
销毁编译器
```

**注意**：
- 可以多次调用 `yrx_compiler_add_source`
- 所有源会被合并到一个规则集中
- `yrx_compiler_build` 会清空编译器状态，可以继续添加新源

---

## 6. test_compiler_with_origin - 带来源信息

```cpp
void test_compiler_with_origin() {
    std::cout << "\n=== Test: Compiler Add Source With Origin ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    const char* rule = "rule test { condition: true }";
    const char* origin = "test_rule.yar";
    
    YRX_RESULT result = yrx_compiler_add_source_with_origin(compiler, rule, origin);
    TEST_ASSERT(result == YRX_SUCCESS, "Add source with origin");
    
    // ...
}
```

### 解读

**origin 参数**：
- 指定规则的来源文件名
- 用于错误报告中显示文件名
- 方便定位错误位置

**错误输出示例**：
```
error[E001]: syntax error
 --> test_rule.yar:4:22
  |
4 |                 $a = "test
  |                      ^^^^^ unclosed literal string
```

---

## 7. test_multiple_compiler_flags - 多个编译器标志

```cpp
void test_multiple_compiler_flags() {
    std::cout << "\n=== Test: Multiple Compiler Flags ===" << std::endl;
    
    uint32_t flags = YRX_COLORIZE_ERRORS | YRX_RELAXED_RE_SYNTAX | YRX_ENABLE_CONDITION_OPTIMIZATION;
    
    YRX_COMPILER* compiler = nullptr;
    YRX_RESULT result = yrx_compiler_create(flags, &compiler);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Create compiler with multiple flags");
    
    // ...
}
```

### 解读

**位运算组合标志**：
```cpp
flags = FLAG_A | FLAG_B | FLAG_C
```
- `|` 是按位或运算
- 多个标志通过位或组合
- `uint32_t` 是 32 位无符号整数

**标志说明**：

| 标志 | 作用 |
|------|------|
| `YRX_COLORIZE_ERRORS` | 错误信息添加 ANSI 颜色代码 |
| `YRX_RELAXED_RE_SYNTAX` | 允许更宽松的正则表达式语法 |
| `YRX_ENABLE_CONDITION_OPTIMIZATION` | 优化条件表达式 |

---

## 8. test_namespace - 命名空间

```cpp
void test_namespace() {
    std::cout << "\n=== Test: Namespace ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_new_namespace(compiler, "my_namespace");
    
    const char* rule = "rule namespaced_rule { condition: true }";
    yrx_compiler_add_source(compiler, rule);
    
    // ...
}
```

### 解读

**命名空间作用**：
- 避免规则名冲突
- 组织规则结构
- 同名规则可以在不同命名空间中存在

**使用示例**：
```
命名空间: default
  - rule test { ... }

命名空间: my_namespace
  - rule test { ... }  // 可以与 default 中的 test 共存
```

**API 说明**：
```cpp
yrx_compiler_new_namespace(compiler, "namespace_name");
```
- 切换到指定命名空间
- 后续添加的规则都在该命名空间中
- 如果命名空间不存在会自动创建

---

## 9. test_empty_rule - 空规则测试

```cpp
void test_empty_rule() {
    std::cout << "\n=== Test: Empty Rule ===" << std::endl;
    
    const char* rule = "rule dummy { condition: true }";
    YRX_RULES* rules = nullptr;
    
    YRX_RESULT result = yrx_compile(rule, &rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile empty rule (condition: true)");
    
    // ...
}
```

### 解读

**最简单的 YARA 规则**：
```yara
rule dummy { condition: true }
```
- 只有规则名和条件
- 没有字符串定义（strings 部分）
- 条件始终为真，匹配所有数据

**用途**：
- 测试编译器基本功能
- 作为占位规则
- 用于需要匹配所有数据的场景

---

## 10. test_rule_iterator - 规则迭代

```cpp
void test_rule_iterator() {
    std::cout << "\n=== Test: Rule Iterator ===" << std::endl;
    
    const char* rule = R"(
        rule rule1 { condition: true }
        rule rule2 { condition: false }
        rule rule3 { condition: true }
    )";
    
    YRX_RULES* rules = nullptr;
    yrx_compile(rule, &rules);
    
    TEST_ASSERT(rules != nullptr, "Compile multiple rules");
    
    if (rules) {
        int count = yrx_rules_count(rules);
        TEST_ASSERT(count == 3, "Rule count is 3");
        
        int iter_count = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* count = static_cast<int*>(user_data);
            (*count)++;
            
            const uint8_t* ident = nullptr;
            size_t len = 0;
            if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
                std::string name(reinterpret_cast<const char*>(ident), len);
                std::cout << "    Found rule: " << name << std::endl;
            }
        };
        
        yrx_rules_iter(rules, callback, &iter_count);
        TEST_ASSERT(iter_count == 3, "Iterated 3 rules");
        
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**Lambda 回调函数**：
```cpp
auto callback = [](const YRX_RULE* rule, void* user_data) {
    // 函数体
};
```
- `[]`：空捕获列表，不捕获外部变量
- 参数由 `yrx_rules_iter` 传入

**迭代流程**：
```
yrx_rules_iter(rules, callback, &iter_count)
    ↓
对每个规则调用 callback
    ↓
callback 中获取规则名称并计数
```

**API 说明**：

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_rules_iter` | rules, callback, user_data | 迭代所有规则 |
| `yrx_rule_identifier` | rule, &ident, &len | 获取规则名称 |

---

## 11. test_compiler_reset - 编译器重置

```cpp
void test_compiler_reset() {
    std::cout << "\n=== Test: Compiler Reset ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_source(compiler, "rule first { condition: true }");
    YRX_RULES* rules1 = yrx_compiler_build(compiler);
    TEST_ASSERT(rules1 != nullptr, "First build");
    
    if (rules1) {
        int count1 = yrx_rules_count(rules1);
        TEST_ASSERT(count1 == 1, "First build has 1 rule");
        yrx_rules_destroy(rules1);
    }
    
    yrx_compiler_add_source(compiler, "rule second { condition: true }");
    YRX_RULES* rules2 = yrx_compiler_build(compiler);
    TEST_ASSERT(rules2 != nullptr, "Second build after reset");
    
    if (rules2) {
        int count2 = yrx_rules_count(rules2);
        TEST_ASSERT(count2 == 1, "Second build has 1 rule");
        yrx_rules_destroy(rules2);
    }
    
    yrx_compiler_destroy(compiler);
}
```

### 解读

**编译器重置行为**：
- `yrx_compiler_build` 调用后会清空编译器状态
- 可以继续添加新的源代码
- 每次构建产生独立的规则集

**流程图**：
```
添加规则1 → 构建 → 得到 rules1 (1条规则)
                ↓
           编译器自动重置
                ↓
添加规则2 → 构建 → 得到 rules2 (1条规则)
```

---

## 12. test_load_rules_from_file - 从文件加载规则

```cpp
void test_load_rules_from_file() {
    std::cout << "\n=== Test: Load Rules From File ===" << std::endl;
    
    std::ifstream file("tests/rules/basic.yar");
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string rule_content = buffer.str();
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule_content.c_str(), &rules);
    
    // ...
}
```

### 解读

**文件读取流程**：

```cpp
// 1. 打开文件
std::ifstream file("tests/rules/basic.yar");

// 2. 创建字符串流
std::stringstream buffer;

// 3. 读取文件内容到流
buffer << file.rdbuf();

// 4. 转换为字符串
std::string rule_content = buffer.str();

// 5. 获取 C 风格字符串指针
rule_content.c_str()
```

**类型说明**：

| 类型 | 说明 |
|------|------|
| `std::ifstream` | 输入文件流 |
| `std::stringstream` | 字符串流 |
| `file.rdbuf()` | 返回文件流缓冲区指针 |
| `buffer.str()` | 返回流中的字符串 |
| `str.c_str()` | 返回 C 风格字符串（const char*） |

---

## 13. test_include_directory - include 目录

```cpp
void test_include_directory() {
    std::cout << "\n=== Test: Include Directory ===" << std::endl;
    
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_add_include_dir(compiler, "tests/rules");
    
    std::ifstream file("tests/rules/with_include.yar");
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string rule_content = buffer.str();
    
    YRX_RESULT result = yrx_compiler_add_source(compiler, rule_content.c_str());
    
    // ...
}
```

### 解读

**include 功能**：
- YARA 支持 `include "other.yar"` 语法
- 可以将规则拆分到多个文件
- `yrx_compiler_add_include_dir` 设置搜索路径

**使用示例**：

主文件 `main.yar`：
```yara
include "common.yar"

rule main_rule {
    condition: common_rule
}
```

被包含文件 `common.yar`：
```yara
rule common_rule {
    condition: true
}
```

**API 说明**：
```cpp
yrx_compiler_add_include_dir(compiler, "path/to/dir");
```
- 可以多次调用添加多个目录
- 按添加顺序搜索

---

## 14. main 函数

```cpp
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  YARA-X CAPI Basic Compile Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    
    test_simple_compile();
    test_compiler_create_destroy();
    test_compiler_add_source();
    test_compiler_with_origin();
    test_multiple_compiler_flags();
    test_namespace();
    test_empty_rule();
    test_rule_iterator();
    test_compiler_reset();
    test_load_rules_from_file();
    test_include_directory();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Test Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Passed: " << tests_passed << std::endl;
    std::cout << "  Failed: " << tests_failed << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
```

### 解读

**返回值**：
- `return 0`：所有测试通过
- `return 1`：有测试失败

**三元运算符**：
```cpp
return tests_failed > 0 ? 1 : 0;
```
- 如果 `tests_failed > 0`，返回 1
- 否则返回 0

---

## 15. API 函数总结

### 编译相关

| 函数 | 作用 |
|------|------|
| `yrx_compile` | 一步完成编译 |
| `yrx_compiler_create` | 创建编译器 |
| `yrx_compiler_destroy` | 销毁编译器 |
| `yrx_compiler_add_source` | 添加源代码 |
| `yrx_compiler_add_source_with_origin` | 添加源代码（带来源信息） |
| `yrx_compiler_build` | 构建规则 |
| `yrx_compiler_new_namespace` | 切换命名空间 |
| `yrx_compiler_add_include_dir` | 添加 include 目录 |

### 规则相关

| 函数 | 作用 |
|------|------|
| `yrx_rules_count` | 获取规则数量 |
| `yrx_rules_iter` | 迭代所有规则 |
| `yrx_rules_destroy` | 销毁规则 |
| `yrx_rule_identifier` | 获取规则名称 |

---

## 16. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    简单编译流程                              │
├─────────────────────────────────────────────────────────────┤
│  yrx_compile(source, &rules)                               │
│           ↓                                                 │
│  使用规则                                                   │
│           ↓                                                 │
│  yrx_rules_destroy(rules)                                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    完整编译流程                              │
├─────────────────────────────────────────────────────────────┤
│  yrx_compiler_create(flags, &compiler)                     │
│           ↓                                                 │
│  yrx_compiler_new_namespace(compiler, "ns") [可选]         │
│           ↓                                                 │
│  yrx_compiler_add_include_dir(compiler, "dir") [可选]      │
│           ↓                                                 │
│  yrx_compiler_add_source(compiler, source) [可多次]        │
│           ↓                                                 │
│  yrx_compiler_build(compiler) → rules                      │
│           ↓                                                 │
│  yrx_compiler_destroy(compiler)                            │
│           ↓                                                 │
│  使用规则                                                   │
│           ↓                                                 │
│  yrx_rules_destroy(rules)                                  │
└─────────────────────────────────────────────────────────────┘
```
