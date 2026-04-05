# test_patterns.cpp 代码解读

本文档详细解读 `test_patterns.cpp` 文件，测试 YARA-X CAPI 的模式匹配功能。

## 文件概述

这个文件包含 15 个测试函数，验证 YARA 的各种模式匹配功能：
- 字符串模式（nocase、wide、fullword）
- 十六进制模式（跳转、通配符）
- 正则表达式
- 条件操作符（count、offset、filesize）

---

## 1. 辅助结构体和函数

### ScanResult 结构体

```cpp
struct ScanResult {
    int match_count;                              // 匹配的规则数量
    std::vector<std::string> matched_rules;       // 匹配的规则名称列表
    std::vector<std::pair<size_t, size_t>> match_offsets;  // 匹配位置和长度
};
```

### 解读

**结构体成员**：

| 成员 | 类型 | 说明 |
|------|------|------|
| `match_count` | `int` | 匹配的规则总数 |
| `matched_rules` | `std::vector<std::string>` | 匹配的规则名称列表 |
| `match_offsets` | `std::vector<std::pair<size_t, size_t>>` | 匹配的偏移和长度对 |

**std::pair 说明**：
```cpp
std::pair<size_t, size_t>
// first = offset (偏移位置)
// second = length (匹配长度)
```

### 回调函数

```cpp
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

### 辅助函数

```cpp
YRX_RULES* compile_rule(const char* rule) {
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_compile(rule, &rules);
    return rules;
}

ScanResult scan_data(YRX_RULES* rules, const uint8_t* data, size_t len) {
    ScanResult result = {0, {}, {}};
    
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    
    yrx_scanner_on_matching_rule(scanner, rule_callback, &result);
    yrx_scanner_scan(scanner, data, len);
    
    yrx_scanner_destroy(scanner);
    
    return result;
}
```

---

## 2. 字符串模式测试

### test_string_pattern - 基本字符串匹配

```cpp
void test_string_pattern() {
    const char* rule = R"(
        rule string_test {
            strings:
                $a = "hello"
            condition:
                $a
        }
    )";
    
    YRX_RULES* rules = compile_rule(rule);
    // ...
    const char* data = "hello world";
    ScanResult result = scan_data(rules, ...);
    // ...
}
```

### 解读

**YARA 规则结构**：
```yara
rule 规则名 {
    strings:           // 定义字符串模式
        $名称 = "模式"
    condition:         // 匹配条件
        $名称          // 表示模式必须匹配
}
```

**匹配逻辑**：
- 数据 `"hello world"` 包含 `"hello"`
- 规则条件 `$a` 表示模式 `$a` 必须存在
- 因此匹配成功

---

### test_nocase_pattern - 不区分大小写

```cpp
void test_nocase_pattern() {
    const char* rule = R"(
        rule nocase_test {
            strings:
                $a = "HELLO" nocase
            condition:
                $a
        }
    )";
    
    // ...
    const char* data = "hello world";  // 小写
    // 匹配成功，因为 nocase 忽略大小写
}
```

### 解读

**字符串修饰符**：

| 修饰符 | 作用 |
|--------|------|
| `nocase` | 不区分大小写 |
| `wide` | 匹配宽字符（UTF-16） |
| `fullword` | 全词匹配 |
| `ascii` | 匹配 ASCII 字符（默认） |
| `xor` | XOR 变体匹配 |

---

### test_wide_pattern - 宽字符匹配

```cpp
void test_wide_pattern() {
    const char* rule = R"(
        rule wide_test {
            strings:
                $a = "hello" wide
            condition:
                $a
        }
    )";
    
    // ...
    const uint8_t wide_data[] = {'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0};
    // 匹配成功
}
```

### 解读

**宽字符编码**：
- Windows 常用 UTF-16LE 编码
- 每个字符占 2 字节
- `'h'` 变成 `0x68, 0x00`

**数据布局**：
```
'h' 0 'e' 0 'l' 0 'l' 0 'o' 0
68 00 65 00 6C 00 6C 00 6F 00
```

---

### test_fullword_pattern - 全词匹配

```cpp
void test_fullword_pattern() {
    const char* rule = R"(
        rule fullword_test {
            strings:
                $a = "test" fullword
            condition:
                $a
        }
    )";
    
    // ...
    const char* data1 = "this is a test string";  // 匹配
    const char* data2 = "this is testing";        // 不匹配
}
```

### 解读

**fullword 匹配规则**：
- 模式前后必须是单词边界
- 单词边界：非字母数字字符或字符串开头/结尾

**示例分析**：
| 数据 | 是否匹配 | 原因 |
|------|----------|------|
| `"test string"` | ✓ | test 前是空格，后是空格 |
| `"testing"` | ✗ | test 后是 ing，不是边界 |
| `"a-test-b"` | ✓ | test 前后是连字符 |

---

## 3. 十六进制模式测试

### test_hex_pattern - 基本十六进制

```cpp
void test_hex_pattern() {
    const char* rule = R"(
        rule hex_test {
            strings:
                $hex = { 48 65 6C 6C 6F }
            condition:
                $hex
        }
    )";
    
    // ...
    const char* data = "Hello World";  // 匹配
}
```

### 解读

**十六进制表示**：
- `{ 48 65 6C 6C 6F }` 是 "Hello" 的 ASCII 码
- 每两个十六进制数字代表一个字节

**ASCII 对照表**：
| 字符 | 十六进制 |
|------|----------|
| H | 48 |
| e | 65 |
| l | 6C |
| l | 6C |
| o | 6F |

---

### test_hex_with_jumps - 跳转语法

```cpp
void test_hex_with_jumps() {
    const char* rule = R"(
        rule hex_jump_test {
            strings:
                $hex = { 48 [2-5] 6F }
            condition:
                $hex
        }
    )";
    
    // ...
    const char* data = "Hello World";  // 匹配
}
```

### 解读

**跳转语法**：
- `[n]`：恰好跳过 n 个字节
- `[n-m]`：跳过 n 到 m 个字节
- `[n-]`：跳过至少 n 个字节

**匹配分析**：
```
数据: H  e  l  l  o     W  o  r  l  d
十六: 48 65 6C 6C 6F 20 57 6F 72 6C 64
      ↑                    ↑
      48                   6F
      
{ 48 [2-5] 6F } 匹配：
- 48 匹配 'H'
- [2-5] 跳过 2-5 个字节
- 6F 匹配 'o'
```

---

### test_hex_wildcard - 通配符

```cpp
void test_hex_wildcard() {
    const char* rule = R"(
        rule hex_wildcard_test {
            strings:
                $hex = { 48 ?? 6C 6F }
            condition:
                $hex
        }
    )";
    
    // ...
    const char* data = "Halo World";  // 匹配
}
```

### 解读

**通配符语法**：
- `??`：匹配任意一个字节
- `?X`：高 4 位任意，低 4 位为 X
- `X?`：高 4 位为 X，低 4 位任意

**匹配分析**：
```
数据: H  a  l  o
十六: 48 61 6C 6F

{ 48 ?? 6C 6F } 匹配：
- 48 匹配 'H'
- ?? 匹配任意字节（这里是 61，即 'a'）
- 6C 匹配 'l'
- 6F 匹配 'o'
```

---

## 4. 正则表达式测试

### test_regex_pattern - 基本正则

```cpp
void test_regex_pattern() {
    const char* rule = R"(
        rule regex_test {
            strings:
                $re = /test.*pattern/
            condition:
                $re
        }
    )";
    
    // ...
    const char* data = "this is a test_pattern example";  // 匹配
}
```

### 解读

**正则语法**：
- YARA 使用 PCRE 风格的正则表达式
- 用 `/pattern/` 包围

**常用正则元字符**：

| 元字符 | 作用 |
|--------|------|
| `.` | 任意字符 |
| `*` | 前面的字符出现 0 次或多次 |
| `+` | 前面的字符出现 1 次或多次 |
| `?` | 前面的字符出现 0 次或 1 次 |
| `\d` | 数字 |
| `\w` | 单词字符 |
| `\s` | 空白字符 |
| `[]` | 字符类 |
| `()` | 分组 |

---

### test_regex_case_insensitive - 不区分大小写正则

```cpp
void test_regex_case_insensitive() {
    const char* rule = R"(
        rule regex_nocase_test {
            strings:
                $re = /HELLO/i
            condition:
                $re
        }
    )";
    
    // ...
    const char* data = "hello world";  // 匹配
}
```

### 解读

**正则修饰符**：

| 修饰符 | 作用 |
|--------|------|
| `i` | 不区分大小写 |
| `s` | 单行模式（`.` 匹配换行） |
| `m` | 多行模式 |

---

## 5. 条件操作符测试

### test_multiple_patterns - 多模式匹配

```cpp
void test_multiple_patterns() {
    const char* rule = R"(
        rule multi_pattern {
            strings:
                $a = "foo"
                $b = "bar"
                $c = "baz"
            condition:
                any of them
        }
    )";
    
    // ...
}
```

### 解读

**条件关键字**：

| 关键字 | 作用 |
|--------|------|
| `any of them` | 任意一个模式匹配 |
| `all of them` | 所有模式都匹配 |
| `none of them` | 没有模式匹配 |

**等价写法**：
```yara
any of them  ≡  $a or $b or $c
all of them  ≡  $a and $b and $c
```

---

### test_all_of - all of 条件

```cpp
void test_all_of() {
    const char* rule = R"(
        rule all_of_test {
            strings:
                $a = "hello"
                $b = "world"
            condition:
                all of them
        }
    )";
    
    // ...
    const char* data1 = "hello world";  // 匹配（两个都有）
    const char* data2 = "hello only";   // 不匹配（只有 hello）
}
```

---

### test_count_operator - 计数操作符

```cpp
void test_count_operator() {
    const char* rule = R"(
        rule count_test {
            strings:
                $a = "test"
            condition:
                #a > 1
        }
    )";
    
    // ...
    const char* data = "test test test";  // 匹配（3次）
}
```

### 解读

**计数操作符 `#`**：
- `#a` 表示模式 `$a` 匹配的次数
- 可以用于条件判断

**示例**：
```yara
#a == 2     // 恰好匹配 2 次
#a > 3      // 匹配超过 3 次
#a >= 1     // 至少匹配 1 次
```

---

### test_offset_operator - 偏移操作符

```cpp
void test_offset_operator() {
    const char* rule = R"(
        rule offset_test {
            strings:
                $a = "test"
            condition:
                @a == 0
        }
    )";
    
    // ...
    const char* data = "test at start";  // 匹配（偏移为 0）
}
```

### 解读

**偏移操作符 `@`**：
- `@a` 表示模式 `$a` 第一次匹配的偏移位置
- 从 0 开始计数

**相关操作符**：

| 操作符 | 作用 |
|--------|------|
| `@a` | 第一次匹配的偏移 |
| `@a[n]` | 第 n 次匹配的偏移 |
| `!a` | 第一次匹配的长度 |
| `!a[n]` | 第 n 次匹配的长度 |

---

### test_filesize_condition - 文件大小条件

```cpp
void test_filesize_condition() {
    const char* rule = R"(
        rule filesize_test {
            condition:
                filesize > 5
        }
    )";
    
    // ...
    const char* data = "hello world";  // 11 字节，匹配
    const char* small_data = "hi";     // 2 字节，不匹配
}
```

### 解读

**filesize 关键字**：
- 表示扫描数据的大小（字节数）
- 可以用于过滤文件

**常用条件**：
```yara
filesize > 1000        // 大于 1KB
filesize < 1024 * 1024 // 小于 1MB
filesize >= 100        // 大于等于 100 字节
```

---

## 6. 匹配位置和长度测试

### test_match_offset_length

```cpp
void test_match_offset_length() {
    const char* rule = R"(
        rule offset_length_test {
            strings:
                $a = "hello"
            condition:
                $a
        }
    )";
    
    // ...
    const char* data = "say hello world";
    
    ScanResult scan_result = {0, {}, {}};
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    
    auto pattern_cb = [](const YRX_PATTERN* pattern, void* user_data) {
        ScanResult* result = static_cast<ScanResult*>(user_data);
        
        auto match_cb = [](const YRX_MATCH* match, void* user_data) {
            ScanResult* result = static_cast<ScanResult*>(user_data);
            result->match_offsets.push_back({match->offset, match->length});
        };
        
        yrx_pattern_iter_matches(pattern, match_cb, user_data);
    };
    
    yrx_scanner_on_matching_rule(scanner, rule_callback, &scan_result);
    yrx_scanner_scan(scanner, ...);
    
    // match_offsets[0].first == 4  (偏移)
    // match_offsets[0].second == 5  (长度)
}
```

### 解读

**匹配位置分析**：
```
数据: s  a  y     h  e  l  l  o     w  o  r  l  d
偏移: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14

"hello" 从偏移 4 开始，长度为 5
```

**嵌套回调**：
```
规则匹配回调 (rule_callback)
    ↓
模式迭代 (yrx_rule_iter_patterns) [可选]
    ↓
模式匹配回调 (pattern_callback)
    ↓
匹配迭代 (yrx_pattern_iter_matches)
    ↓
匹配回调 (match_callback)
```

---

## 7. YARA 模式语法总结

### 字符串模式

```yara
$a = "literal"              // 字面字符串
$a = "nocase" nocase        // 不区分大小写
$a = "wide" wide            // 宽字符
$a = "fullword" fullword    // 全词匹配
$a = "multi" ascii wide     // 多修饰符
```

### 十六进制模式

```yara
$hex = { 48 65 6C 6C 6F }           // 精确匹配
$hex = { 48 ?? 6C 6F }              // 通配符
$hex = { 48 [2-5] 6F }              // 跳转
$hex = { 48 65 [10-] 6F }           // 无限跳转
$hex = { ( 48 65 | 65 48 ) }        // 或运算
```

### 正则表达式

```yara
$re = /test/               // 基本正则
$re = /test.*pattern/i     // 不区分大小写
$re = /\d{3}-\d{4}/        // 数字模式
```

---

## 8. 条件表达式总结

### 基本条件

```yara
$a                          // 模式匹配
$a and $b                   // 逻辑与
$a or $b                    // 逻辑或
not $a                      // 逻辑非
```

### 集合条件

```yara
any of them                 // 任意一个
all of them                 // 全部
any of ($a, $b, $c)         // 指定集合中任意一个
all of ($a, $b, $c)         // 指定集合中全部
```

### 计数和偏移

```yara
#a                          // 匹配次数
@a                          // 第一次匹配偏移
@a[2]                       // 第二次匹配偏移
!a                          // 第一次匹配长度
!a[2]                       // 第二次匹配长度
```

### 文件属性

```yara
filesize                    // 文件大小
entrypoint                  // 入口点（PE 文件）
```

---

## 9. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    模式匹配流程                              │
├─────────────────────────────────────────────────────────────┤
│  1. 编译规则 (yrx_compile)                                  │
│           ↓                                                 │
│  2. 创建扫描器 (yrx_scanner_create)                         │
│           ↓                                                 │
│  3. 设置回调 (yrx_scanner_on_matching_rule)                │
│           ↓                                                 │
│  4. 执行扫描 (yrx_scanner_scan)                             │
│           ↓                                                 │
│  5. 匹配时回调被触发                                        │
│           ↓                                                 │
│  6. 销毁扫描器和规则                                        │
└─────────────────────────────────────────────────────────────┘
```
