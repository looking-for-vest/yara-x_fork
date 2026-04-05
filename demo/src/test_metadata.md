# test_metadata.cpp 代码解读

本文档详细解读 `test_metadata.cpp` 文件，测试 YARA-X CAPI 的元数据和标签功能。

## 文件概述

这个文件包含 8 个测试函数，验证：
- 字符串元数据
- 整数元数据
- 浮点数元数据
- 布尔元数据
- 混合类型元数据
- 无元数据规则
- 标签
- 命名空间

---

## 1. 数据结构定义

### MetadataInfo 结构体

```cpp
struct MetadataInfo {
    std::string identifier;      // 元数据名称
    YRX_METADATA_TYPE type;      // 元数据类型
    std::string str_value;       // 字符串值
    int64_t int_value;           // 整数值
    double float_value;          // 浮点数值
    bool bool_value;             // 布尔值
};
```

### 解读

**成员说明**：

| 成员 | 类型 | 说明 |
|------|------|------|
| `identifier` | `std::string` | 元数据的键名（如 "author"） |
| `type` | `YRX_METADATA_TYPE` | 元数据类型枚举 |
| `str_value` | `std::string` | 当类型为字符串时的值 |
| `int_value` | `int64_t` | 当类型为整数时的值 |
| `float_value` | `double` | 当类型为浮点数时的值 |
| `bool_value` | `bool` | 当类型为布尔值时的值 |

**YRX_METADATA_TYPE 枚举**：

| 枚举值 | 说明 |
|--------|------|
| `YRX_I64` | 64 位整数 |
| `YRX_F64` | 64 位浮点数 |
| `YRX_BOOLEAN` | 布尔值 |
| `YRX_STRING` | 字符串 |
| `YRX_BYTES` | 字节数组 |

---

### RuleMetadata 结构体

```cpp
struct RuleMetadata {
    std::string rule_name;              // 规则名称
    std::vector<MetadataInfo> metadata_list;  // 元数据列表
};
```

---

## 2. 规则回调函数

```cpp
void rule_callback(const YRX_RULE* rule, void* user_data) {
    std::vector<RuleMetadata>* results = static_cast<std::vector<RuleMetadata>*>(user_data);
    
    RuleMetadata rm;
    
    // 获取规则名称
    const uint8_t* ident = nullptr;
    size_t len = 0;
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        rm.rule_name = std::string(reinterpret_cast<const char*>(ident), len);
    }
    
    // 元数据回调
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
```

### 解读

**YRX_METADATA 结构体**：

```cpp
struct YRX_METADATA {
    const char* identifier;       // 元数据名称
    YRX_METADATA_TYPE value_type; // 值类型
    union {
        int64_t i64;
        double f64;
        bool boolean;
        const char* string;
        struct {
            const uint8_t* data;
            size_t length;
        } bytes;
    } value;
};
```

**switch 语句说明**：
- 根据元数据类型选择对应的值字段
- `union` 是共用体，同一时间只有一个成员有效

**API 函数**：

| 函数 | 作用 |
|------|------|
| `yrx_rule_identifier` | 获取规则名称 |
| `yrx_rule_iter_metadata` | 迭代规则的所有元数据 |

---

## 3. 字符串元数据测试

```cpp
void test_string_metadata() {
    const char* rule = R"(
        rule string_meta {
            meta:
                author = "Test Author"
                description = "This is a test rule"
            condition:
                true
        }
    )";
    
    // ...
}
```

### 解读

**YARA 元数据语法**：
```yara
meta:
    key = value
```

**字符串元数据**：
- 用双引号包围
- 支持任意文本内容
- 常用于记录作者、描述、版本等信息

**常见用途**：
| 元数据键 | 用途 |
|----------|------|
| `author` | 规则作者 |
| `description` | 规则描述 |
| `version` | 版本号 |
| `date` | 创建日期 |
| `reference` | 参考链接 |

---

## 4. 整数元数据测试

```cpp
void test_integer_metadata() {
    const char* rule = R"(
        rule int_meta {
            meta:
                version = 42
                count = 100
            condition:
                true
        }
    )";
    
    // ...
}
```

### 解读

**整数元数据**：
- 直接写数字，不加引号
- 自动识别为整数类型
- 存储为 64 位有符号整数（`int64_t`）

**支持的范围**：
- 最小值：-9,223,372,036,854,775,808
- 最大值：9,223,372,036,854,775,807

---

## 5. 浮点数元数据测试

```cpp
void test_float_metadata() {
    const char* rule = R"(
        rule float_meta {
            meta:
                ratio = 3.14159
                threshold = 0.5
            condition:
                true
        }
    )";
    
    // ...
}
```

### 解读

**浮点数元数据**：
- 包含小数点的数字
- 自动识别为浮点类型
- 存储为 64 位双精度浮点数（`double`）

**浮点数比较**：
```cpp
TEST_ASSERT(m.float_value > 3.14 && m.float_value < 3.15, "...");
```
- 由于浮点精度问题，通常使用范围比较
- 不建议直接用 `==` 比较浮点数

---

## 6. 布尔元数据测试

```cpp
void test_boolean_metadata() {
    const char* rule = R"(
        rule bool_meta {
            meta:
                enabled = true
                disabled = false
            condition:
                true
        }
    )";
    
    // ...
}
```

### 解读

**布尔元数据**：
- 值为 `true` 或 `false`
- 不加引号
- 常用于开关配置

**常见用途**：
| 元数据键 | 用途 |
|----------|------|
| `enabled` | 是否启用 |
| `deprecated` | 是否已弃用 |
| `critical` | 是否关键规则 |

---

## 7. 混合类型元数据测试

```cpp
void test_mixed_metadata() {
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
    
    // ...
}
```

### 解读

**混合类型**：
- 一个规则可以有多个不同类型的元数据
- 每个元数据独立存储类型信息

**使用 std::map 检查类型**：
```cpp
std::map<std::string, YRX_METADATA_TYPE> types;
for (const auto& m : results[0].metadata_list) {
    types[m.identifier] = m.type;
}

TEST_ASSERT(types["author"] == YRX_STRING, "author is string");
TEST_ASSERT(types["version"] == YRX_I64, "version is integer");
```

**std::map 说明**：
- 键值对容器
- `types["key"]` 访问或插入元素
- 自动按键排序

---

## 8. 无元数据测试

```cpp
void test_no_metadata() {
    const char* rule = R"(
        rule no_meta {
            condition:
                true
        }
    )";
    
    // ...
    TEST_ASSERT(results[0].metadata_list.empty(), "No metadata entries");
}
```

### 解读

**无 meta 部分的规则**：
- 元数据是可选的
- `metadata_list` 为空

**vector::empty()**：
- 检查容器是否为空
- 返回 `true` 如果大小为 0

---

## 9. 标签测试

### 数据结构

```cpp
struct TagData {
    std::string rule_name;
    std::vector<std::string> tags;
};
```

### 回调函数

```cpp
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
```

### 测试函数

```cpp
void test_tags() {
    const char* rule = R"(
        rule tagged_rule : tag1 tag2 tag3 {
            condition:
                true
        }
    )";
    
    // ...
}
```

### 解读

**YARA 标签语法**：
```yara
rule 规则名 : 标签1 标签2 标签3 {
    // ...
}
```

**标签特点**：
- 在规则名后用冒号分隔
- 多个标签用空格分隔
- 用于规则分类和过滤

**API 函数**：

| 函数 | 作用 |
|------|------|
| `yrx_rule_iter_tags` | 迭代规则的所有标签 |

**标签 vs 元数据**：

| 特性 | 标签 | 元数据 |
|------|------|--------|
| 语法位置 | 规则名后 | meta 部分 |
| 值类型 | 仅字符串 | 多种类型 |
| 用途 | 分类、过滤 | 详细信息 |
| 访问方式 | `yrx_rule_iter_tags` | `yrx_rule_iter_metadata` |

---

## 10. 命名空间测试

```cpp
void test_namespace() {
    YRX_COMPILER* compiler = nullptr;
    yrx_compiler_create(0, &compiler);
    
    yrx_compiler_new_namespace(compiler, "custom_namespace");
    yrx_compiler_add_source(compiler, "rule namespaced { condition: true }");
    
    YRX_RULES* rules = yrx_compiler_build(compiler);
    yrx_compiler_destroy(compiler);
    
    // ...
}
```

### 解读

**命名空间用途**：
- 组织规则结构
- 避免规则名冲突
- 不同命名空间可以有同名规则

**API 函数**：

| 函数 | 作用 |
|------|------|
| `yrx_compiler_new_namespace` | 切换到指定命名空间 |
| `yrx_rule_namespace` | 获取规则所属命名空间 |

**命名空间示例**：
```
命名空间: malware
  - rule trojan { ... }
  - rule ransomware { ... }

命名空间: benign
  - rule trojan { ... }  // 可以与 malware 中的同名
```

---

## 11. YARA 元数据语法总结

### 基本语法

```yara
rule 规则名 : 标签1 标签2 {
    meta:
        字符串元数据 = "value"
        整数元数据 = 42
        浮点元数据 = 3.14
        布尔元数据 = true
    strings:
        $a = "pattern"
    condition:
        $a
}
```

### 元数据类型识别

| 写法 | 类型 |
|------|------|
| `"text"` | 字符串 |
| `42` | 整数 |
| `3.14` | 浮点数 |
| `true` / `false` | 布尔 |

### 最佳实践

1. **命名规范**：
   - 使用小写字母和下划线
   - 例：`author`、`created_date`、`rule_version`

2. **常用元数据**：
   ```yara
   meta:
       author = "Security Team"
       date = "2024-01-15"
       version = 1
       severity = "high"
       reference = "https://example.com/malware-info"
   ```

3. **标签分类**：
   ```yara
   rule example : malware trojan windows {
       // ...
   }
   ```

---

## 12. API 函数总结

### 元数据相关

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_rule_iter_metadata` | rule, callback, user_data | 迭代规则元数据 |

### 标签相关

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_rule_iter_tags` | rule, callback, user_data | 迭代规则标签 |

### 命名空间相关

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_compiler_new_namespace` | compiler, name | 切换命名空间 |
| `yrx_rule_namespace` | rule, &ns, &len | 获取规则命名空间 |

---

## 13. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    元数据获取流程                            │
├─────────────────────────────────────────────────────────────┤
│  1. 编译规则（包含 meta 部分）                              │
│           ↓                                                 │
│  2. 创建扫描器                                              │
│           ↓                                                 │
│  3. 设置规则匹配回调                                        │
│           ↓                                                 │
│  4. 执行扫描                                                │
│           ↓                                                 │
│  5. 规则匹配时回调被触发                                    │
│           ↓                                                 │
│  6. 在回调中调用 yrx_rule_iter_metadata                    │
│           ↓                                                 │
│  7. 每个元数据触发元数据回调                                │
│           ↓                                                 │
│  8. 根据 value_type 读取对应值                              │
└─────────────────────────────────────────────────────────────┘
```
