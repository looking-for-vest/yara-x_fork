# test_serialization.cpp 代码解读

本文档详细解读 `test_serialization.cpp` 文件，测试 YARA-X CAPI 的序列化和反序列化功能。

## 文件概述

这个文件包含 7 个测试函数，验证：
- 基本序列化/反序列化
- 多规则序列化
- 复杂模式序列化
- 元数据序列化
- 大型规则集序列化
- 无效数据处理
- 文件存储和加载

---

## 1. 序列化概念

### 什么是序列化？

序列化是将编译后的规则转换为二进制格式的过程，可以：
- 保存到文件
- 网络传输
- 缓存编译结果

### 为什么需要序列化？

| 场景 | 说明 |
|------|------|
| **性能优化** | 避免每次启动都重新编译规则 |
| **规则分发** | 将编译好的规则发送给其他系统 |
| **规则保护** | 隐藏规则源码，只分发编译结果 |
| **快速加载** | 直接加载二进制比编译快得多 |

---

## 2. test_serialize_deserialize - 基本序列化

```cpp
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
```

### 解读

**YRX_BUFFER 结构体**：

```cpp
struct YRX_BUFFER {
    uint8_t* data;    // 指向数据的指针
    size_t length;    // 数据长度
};
```

**API 函数**：

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_rules_serialize` | rules, &buffer | 序列化规则到缓冲区 |
| `yrx_rules_deserialize` | data, length, &rules | 从缓冲区反序列化规则 |
| `yrx_buffer_destroy` | buffer | 销毁缓冲区 |

**序列化流程**：

```
编译规则 (yrx_compile)
        ↓
序列化 (yrx_rules_serialize)
        ↓
获取 YRX_BUFFER
        ↓
使用 buffer->data 和 buffer->length
        ↓
反序列化 (yrx_rules_deserialize)
        ↓
使用反序列化的规则
        ↓
销毁缓冲区和规则
```

---

## 3. test_serialize_multiple_rules - 多规则序列化

```cpp
void test_serialize_multiple_rules() {
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
        
        // 序列化和反序列化...
        int deserialized_count = yrx_rules_count(deserialized_rules);
        TEST_ASSERT(deserialized_count == original_count, "Rule count preserved");
    }
}
```

### 解读

**yrx_rules_count 函数**：

```cpp
int count = yrx_rules_count(rules);
```

- 返回规则集中的规则数量
- 用于验证序列化前后规则数量一致

---

## 4. test_serialize_with_patterns - 复杂模式序列化

```cpp
void test_serialize_with_patterns() {
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
    
    // 序列化和反序列化...
    
    const char* data = "hello world";
    // 扫描验证...
    TEST_ASSERT(scan_result.match_count == 1, "Complex patterns work after deserialize");
}
```

### 解读

**验证复杂模式**：
- 字符串模式
- 十六进制模式
- 正则表达式模式

序列化后这些模式应该保持完整功能。

---

## 5. test_serialize_with_metadata - 元数据序列化

```cpp
void test_serialize_with_metadata() {
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
    
    // 序列化和反序列化...
    
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
}
```

### 解读

**元数据验证**：
- 序列化后元数据完整保留
- 所有类型（字符串、整数、布尔）都正确保存

---

## 6. test_serialize_large_ruleset - 大型规则集序列化

```cpp
void test_serialize_large_ruleset() {
    std::string rules;
    for (int i = 0; i < 100; i++) {
        rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
    }
    
    YRX_RULES* original_rules = nullptr;
    YRX_RESULT result = yrx_compile(rules.c_str(), &original_rules);
    TEST_ASSERT(result == YRX_SUCCESS, "Compile 100 rules");
    
    // ...
    
    std::cout << "    Serialized 100 rules: " << buffer->length << " bytes" << std::endl;
    
    // ...
}
```

### 解读

**动态生成规则字符串**：

```cpp
std::string rules;
for (int i = 0; i < 100; i++) {
    rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
}
```

**std::to_string**：
- 将数字转换为字符串
- `std::to_string(42)` → `"42"`

**性能考虑**：
- 大型规则集序列化后体积较大
- 但加载速度比重新编译快很多

---

## 7. test_deserialize_invalid_data - 无效数据处理

```cpp
void test_deserialize_invalid_data() {
    std::cout << "\n=== Test: Deserialize Invalid Data ===" << std::endl;
    
    uint8_t invalid_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    
    YRX_RULES* rules = nullptr;
    YRX_RESULT result = yrx_rules_deserialize(invalid_data, sizeof(invalid_data), &rules);
    
    TEST_ASSERT(result != YRX_SUCCESS, "Deserialize invalid data fails");
    TEST_ASSERT(rules == nullptr, "Rules is null on failure");
    
    std::cout << "    Error: " << yrx_last_error() << std::endl;
}
```

### 解读

**错误处理**：
- 无效数据反序列化会失败
- 返回错误码（非 YRX_SUCCESS）
- rules 指针保持 nullptr

**yrx_last_error 函数**：

```cpp
const char* error = yrx_last_error();
```

- 获取最近一次错误的描述信息
- 返回错误消息字符串

---

## 8. test_serialize_to_file - 文件存储

```cpp
void test_serialize_to_file() {
    // 编译和序列化...
    
    if (buffer) {
        FILE* f = fopen("tests/data/serialized_rules.bin", "wb");
        if (f) {
            size_t written = fwrite(buffer->data, 1, buffer->length, f);
            fclose(f);
            
            TEST_ASSERT(written == buffer->length, "Write to file successful");
            
            // 从文件读取
            f = fopen("tests/data/serialized_rules.bin", "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long file_size = ftell(f);
                fseek(f, 0, SEEK_SET);
                
                std::vector<uint8_t> file_data(file_size);
                size_t read_size = fread(file_data.data(), 1, file_size, f);
                fclose(f);
                
                // 反序列化...
                YRX_RULES* loaded_rules = nullptr;
                result = yrx_rules_deserialize(file_data.data(), file_data.size(), &loaded_rules);
                TEST_ASSERT(result == YRX_SUCCESS, "Deserialize from file");
            }
        }
    }
}
```

### 解读

**C 文件操作函数**：

| 函数 | 作用 |
|------|------|
| `fopen(path, mode)` | 打开文件 |
| `fwrite(ptr, size, count, stream)` | 写入文件 |
| `fread(ptr, size, count, stream)` | 读取文件 |
| `fseek(stream, offset, origin)` | 移动文件指针 |
| `ftell(stream)` | 获取当前位置 |
| `fclose(stream)` | 关闭文件 |

**文件模式**：

| 模式 | 说明 |
|------|------|
| `"rb"` | 二进制读 |
| `"wb"` | 二进制写 |

**获取文件大小**：

```cpp
fseek(f, 0, SEEK_END);    // 移动到文件末尾
long file_size = ftell(f); // 获取当前位置（即文件大小）
fseek(f, 0, SEEK_SET);    // 移动回文件开头
```

**std::vector 文件读取**：

```cpp
std::vector<uint8_t> file_data(file_size);  // 预分配空间
fread(file_data.data(), 1, file_size, f);   // 读取到 vector
```

---

## 9. API 函数总结

### 序列化相关

| 函数 | 参数 | 返回值 | 作用 |
|------|------|--------|------|
| `yrx_rules_serialize` | rules, &buffer | YRX_RESULT | 序列化规则 |
| `yrx_rules_deserialize` | data, length, &rules | YRX_RESULT | 反序列化规则 |
| `yrx_buffer_destroy` | buffer | void | 销毁缓冲区 |
| `yrx_rules_count` | rules | int | 获取规则数量 |

### 错误处理

| 函数 | 作用 |
|------|------|
| `yrx_last_error` | 获取最近错误信息 |

---

## 10. 使用场景

### 场景 1：规则缓存

```cpp
bool load_cached_rules(const char* cache_path, YRX_RULES** rules) {
    FILE* f = fopen(cache_path, "rb");
    if (!f) return false;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);
    
    return yrx_rules_deserialize(data.data(), data.size(), rules) == YRX_SUCCESS;
}

void save_rules_cache(const char* cache_path, YRX_RULES* rules) {
    YRX_BUFFER* buffer = nullptr;
    yrx_rules_serialize(rules, &buffer);
    
    FILE* f = fopen(cache_path, "wb");
    fwrite(buffer->data, 1, buffer->length, f);
    fclose(f);
    
    yrx_buffer_destroy(buffer);
}
```

### 场景 2：规则分发

```cpp
// 服务端：编译规则并序列化
YRX_BUFFER* serialize_rules_for_distribution(const char* rule_source) {
    YRX_RULES* rules = nullptr;
    yrx_compile(rule_source, &rules);
    
    YRX_BUFFER* buffer = nullptr;
    yrx_rules_serialize(rules, &buffer);
    
    yrx_rules_destroy(rules);
    return buffer;
}

// 客户端：接收并反序列化
YRX_RULES* load_distributed_rules(const uint8_t* data, size_t len) {
    YRX_RULES* rules = nullptr;
    yrx_rules_deserialize(data, len, &rules);
    return rules;
}
```

### 场景 3：规则保护

```cpp
// 只分发编译后的规则，不暴露源码
void distribute_compiled_rules(const char* output_path) {
    // 编译敏感规则
    YRX_RULES* rules = nullptr;
    yrx_compile(sensitive_rules, &rules);
    
    // 序列化
    YRX_BUFFER* buffer = nullptr;
    yrx_rules_serialize(rules, &buffer);
    
    // 保存二进制格式
    save_to_file(output_path, buffer);
    
    // 清理
    yrx_buffer_destroy(buffer);
    yrx_rules_destroy(rules);
}
```

---

## 11. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    序列化流程                                │
├─────────────────────────────────────────────────────────────┤
│  1. 编译规则 (yrx_compile)                                  │
│           ↓                                                 │
│  2. 序列化 (yrx_rules_serialize)                            │
│           ↓                                                 │
│  3. 获取 YRX_BUFFER                                         │
│           ↓                                                 │
│  4. 保存到文件/网络传输                                     │
│           ↓                                                 │
│  5. 销毁缓冲区 (yrx_buffer_destroy)                         │
│           ↓                                                 │
│  6. 销毁规则 (yrx_rules_destroy)                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    反序列化流程                              │
├─────────────────────────────────────────────────────────────┤
│  1. 从文件/网络读取二进制数据                               │
│           ↓                                                 │
│  2. 反序列化 (yrx_rules_deserialize)                        │
│           ↓                                                 │
│  3. 获取 YRX_RULES                                          │
│           ↓                                                 │
│  4. 创建扫描器并使用                                        │
│           ↓                                                 │
│  5. 销毁规则 (yrx_rules_destroy)                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 12. 注意事项

1. **内存管理**：
   - 序列化后必须调用 `yrx_buffer_destroy` 释放缓冲区
   - 反序列化后必须调用 `yrx_rules_destroy` 释放规则

2. **错误处理**：
   - 始终检查返回值是否为 `YRX_SUCCESS`
   - 使用 `yrx_last_error` 获取详细错误信息

3. **版本兼容性**：
   - 序列化格式可能与 YARA-X 版本相关
   - 不同版本间可能不兼容

4. **安全性**：
   - 不要反序列化不可信来源的数据
   - 可能存在安全风险

5. **性能**：
   - 序列化后的规则加载比编译快
   - 适合需要频繁加载规则的场景
