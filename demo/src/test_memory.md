# test_memory.cpp 代码解读

本文档详细解读 `test_memory.cpp` 文件，测试 YARA-X CAPI 的内存管理功能。

## 文件概述

这个文件包含 11 个测试函数，验证：
- 编译器生命周期
- 规则生命周期
- 扫描器生命周期
- 销毁顺序
- 多扫描器管理
- 缓冲区生命周期
- 大型规则集处理
- 重复扫描
- 多线程扫描
- 压力测试
- 空数据处理

---

## 1. 内存管理概念

### YARA-X CAPI 对象生命周期

```
编译器 (YRX_COMPILER)
    ↓ build
规则 (YRX_RULES)
    ↓ create
扫描器 (YRX_SCANNER)
    ↓ scan
结果
```

### 销毁顺序

```
扫描器销毁 (yrx_scanner_destroy)
    ↓
规则销毁 (yrx_rules_destroy)
    ↓
编译器销毁 (yrx_compiler_destroy)
```

**重要**：必须先销毁依赖对象，再销毁被依赖对象。

---

## 2. test_compiler_lifecycle - 编译器生命周期

```cpp
void test_compiler_lifecycle() {
    std::cout << "\n=== Test: Compiler Lifecycle ===" << std::endl;
    
    for (int i = 0; i < 100; i++) {
        YRX_COMPILER* compiler = nullptr;
        YRX_RESULT result = yrx_compiler_create(0, &compiler);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Compiler creation failed in loop");
            return;
        }
        
        yrx_compiler_add_source(compiler, "rule test { condition: true }");
        YRX_RULES* rules = yrx_compiler_build(compiler);
        
        if (rules) {
            yrx_rules_destroy(rules);
        }
        
        yrx_compiler_destroy(compiler);
    }
    
    TEST_ASSERT(true, "100 compiler create/destroy cycles completed");
}
```

### 解读

**生命周期流程**：
```
yrx_compiler_create  →  创建编译器
        ↓
yrx_compiler_add_source  →  添加源码
        ↓
yrx_compiler_build  →  构建规则
        ↓
yrx_rules_destroy  →  销毁规则
        ↓
yrx_compiler_destroy  →  销毁编译器
```

**循环测试目的**：
- 验证内存正确释放
- 检测内存泄漏
- 确保重复创建/销毁稳定

---

## 3. test_rules_lifecycle - 规则生命周期

```cpp
void test_rules_lifecycle() {
    std::cout << "\n=== Test: Rules Lifecycle ===" << std::endl;
    
    for (int i = 0; i < 100; i++) {
        YRX_RULES* rules = nullptr;
        YRX_RESULT result = yrx_compile("rule test { condition: true }", &rules);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Rules creation failed in loop");
            return;
        }
        
        yrx_rules_destroy(rules);
    }
    
    TEST_ASSERT(true, "100 rules create/destroy cycles completed");
}
```

### 解读

**简化编译流程**：
```cpp
yrx_compile(source, &rules);  // 一步编译
```

等价于：
```cpp
yrx_compiler_create(...);
yrx_compiler_add_source(...);
yrx_compiler_build(...);
yrx_compiler_destroy(...);
```

---

## 4. test_scanner_lifecycle - 扫描器生命周期

```cpp
void test_scanner_lifecycle() {
    std::cout << "\n=== Test: Scanner Lifecycle ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (!rules) {
        TEST_ASSERT(false, "Failed to compile rules");
        return;
    }
    
    for (int i = 0; i < 100; i++) {
        YRX_SCANNER* scanner = nullptr;
        YRX_RESULT result = yrx_scanner_create(rules, &scanner);
        if (result != YRX_SUCCESS) {
            TEST_ASSERT(false, "Scanner creation failed in loop");
            break;
        }
        
        const char* data = "test data";
        yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        
        yrx_scanner_destroy(scanner);
    }
    
    yrx_rules_destroy(rules);
    TEST_ASSERT(true, "100 scanner create/destroy cycles completed");
}
```

### 解读

**扫描器复用规则**：
- 一个规则可以创建多个扫描器
- 规则在扫描器销毁前必须保持有效
- 扫描器可以重复使用

---

## 5. test_destruction_order - 销毁顺序

```cpp
void test_destruction_order() {
    std::cout << "\n=== Test: Destruction Order ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    TEST_ASSERT(rules != nullptr, "Rules created");
    
    YRX_SCANNER* scanner = nullptr;
    yrx_scanner_create(rules, &scanner);
    TEST_ASSERT(scanner != nullptr, "Scanner created");
    
    yrx_scanner_destroy(scanner);
    std::cout << "  [INFO] Scanner destroyed first" << std::endl;
    
    yrx_rules_destroy(rules);
    std::cout << "  [INFO] Rules destroyed second" << std::endl;
    
    TEST_ASSERT(true, "Correct destruction order: scanner before rules");
}
```

### 解读

**正确的销毁顺序**：
```
1. 销毁扫描器 (依赖规则)
2. 销毁规则 (独立存在)
```

**错误的销毁顺序**：
```
❌ 先销毁规则，再销毁扫描器
   → 扫描器引用已销毁的规则
   → 可能导致崩溃
```

---

## 6. test_multiple_scanners - 多扫描器

```cpp
void test_multiple_scanners() {
    std::cout << "\n=== Test: Multiple Scanners ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    TEST_ASSERT(rules != nullptr, "Rules created");
    
    const int num_scanners = 10;
    std::vector<YRX_SCANNER*> scanners(num_scanners);
    
    for (int i = 0; i < num_scanners; i++) {
        YRX_RESULT result = yrx_scanner_create(rules, &scanners[i]);
        TEST_ASSERT(result == YRX_SUCCESS, "Scanner created");
    }
    
    for (int i = 0; i < num_scanners; i++) {
        const char* data = "test data";
        yrx_scanner_scan(scanners[i], reinterpret_cast<const uint8_t*>(data), strlen(data));
    }
    
    for (int i = 0; i < num_scanners; i++) {
        yrx_scanner_destroy(scanners[i]);
    }
    
    yrx_rules_destroy(rules);
    TEST_ASSERT(true, "Multiple scanners created and destroyed");
}
```

### 解读

**std::vector 存储指针**：
```cpp
std::vector<YRX_SCANNER*> scanners(num_scanners);
```

- 创建包含 `num_scanners` 个元素的 vector
- 每个元素是一个 `YRX_SCANNER*` 指针

**多扫描器用途**：
- 多线程扫描
- 并行处理多个文件
- 不同扫描配置

---

## 7. test_buffer_lifecycle - 缓冲区生命周期

```cpp
void test_buffer_lifecycle() {
    std::cout << "\n=== Test: Buffer Lifecycle ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (rules) {
        for (int i = 0; i < 50; i++) {
            YRX_BUFFER* buffer = nullptr;
            YRX_RESULT result = yrx_rules_serialize(rules, &buffer);
            
            if (result == YRX_SUCCESS && buffer) {
                yrx_buffer_destroy(buffer);
            }
        }
        
        yrx_rules_destroy(rules);
        TEST_ASSERT(true, "50 buffer create/destroy cycles completed");
    }
}
```

### 解读

**缓冲区用途**：
- 序列化规则
- 临时存储二进制数据

**内存管理**：
```cpp
YRX_BUFFER* buffer = nullptr;
yrx_rules_serialize(rules, &buffer);  // 创建缓冲区
// 使用 buffer...
yrx_buffer_destroy(buffer);           // 销毁缓冲区
```

---

## 8. test_large_ruleset - 大型规则集

```cpp
void test_large_ruleset() {
    std::cout << "\n=== Test: Large Rule Set ===" << std::endl;
    
    std::string rules;
    for (int i = 0; i < 1000; i++) {
        rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
    }
    
    YRX_RULES* compiled_rules = nullptr;
    YRX_RESULT result = yrx_compile(rules.c_str(), &compiled_rules);
    
    TEST_ASSERT(result == YRX_SUCCESS, "Compile 1000 rules");
    
    if (compiled_rules) {
        int count = yrx_rules_count(compiled_rules);
        TEST_ASSERT(count == 1000, "Rule count is 1000");
        
        yrx_rules_destroy(compiled_rules);
    }
}
```

### 解读

**动态构建规则字符串**：
```cpp
std::string rules;
for (int i = 0; i < 1000; i++) {
    rules += "rule rule_" + std::to_string(i) + " { condition: true }\n";
}
```

**std::string::c_str()**：
```cpp
rules.c_str()  // 返回 C 风格字符串（const char*）
```

**大型规则集考虑**：
- 内存占用
- 编译时间
- 扫描性能

---

## 9. test_repeated_scans - 重复扫描

```cpp
void test_repeated_scans() {
    std::cout << "\n=== Test: Repeated Scans ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { strings: $a = \"test\" condition: $a }", &rules);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        int match_count = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* count = static_cast<int*>(user_data);
            (*count)++;
        };
        
        const char* data = "test data";
        for (int i = 0; i < 1000; i++) {
            match_count = 0;
            yrx_scanner_on_matching_rule(scanner, callback, &match_count);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
        }
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        
        TEST_ASSERT(true, "1000 repeated scans completed");
    }
}
```

### 解读

**扫描器复用**：
- 一个扫描器可以执行多次扫描
- 每次扫描前可以设置不同的回调
- 复用扫描器比重复创建/销毁更高效

**Lambda 回调**：
```cpp
auto callback = [](const YRX_RULE* rule, void* user_data) {
    int* count = static_cast<int*>(user_data);
    (*count)++;
};
```

- `[]`：不捕获外部变量
- 可以转换为 C 函数指针

---

## 10. test_multithreaded_scanning - 多线程扫描

```cpp
void test_multithreaded_scanning() {
    std::cout << "\n=== Test: Multithreaded Scanning ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (!rules) {
        TEST_ASSERT(false, "Failed to compile rules");
        return;
    }
    
    const int num_threads = 4;
    const int scans_per_thread = 100;
    
    std::atomic<int> total_scans(0);
    std::atomic<int> total_matches(0);
    
    auto scan_worker = [&rules, &total_scans, &total_matches, scans_per_thread]() {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        int matches = 0;
        auto callback = [](const YRX_RULE* rule, void* user_data) {
            int* m = static_cast<int*>(user_data);
            (*m)++;
        };
        
        const char* data = "test data";
        for (int i = 0; i < scans_per_thread; i++) {
            matches = 0;
            yrx_scanner_on_matching_rule(scanner, callback, &matches);
            yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            total_matches += matches;
            total_scans++;
        }
        
        yrx_scanner_destroy(scanner);
    };
    
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(scan_worker);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    yrx_rules_destroy(rules);
    
    TEST_ASSERT(total_scans == num_threads * scans_per_thread, "All scans completed");
    TEST_ASSERT(total_matches == num_threads * scans_per_thread, "All matches found");
}
```

### 解读

**std::atomic 原子变量**：
```cpp
std::atomic<int> total_scans(0);
```

- 线程安全的整数
- 不需要互斥锁
- 支持 `++`、`+=` 等操作

**Lambda 捕获**：
```cpp
auto scan_worker = [&rules, &total_scans, &total_matches, scans_per_thread]() {
    // ...
};
```

- `[&rules]`：引用捕获 rules
- `[scans_per_thread]`：值捕获

**std::thread**：
```cpp
std::vector<std::thread> threads;
threads.emplace_back(scan_worker);  // 创建线程

for (auto& t : threads) {
    t.join();  // 等待线程完成
}
```

**多线程规则**：
- 规则对象可以多线程共享（只读）
- 每个线程使用独立的扫描器
- 扫描器不能跨线程共享

---

## 11. test_stress_test - 压力测试

```cpp
void test_stress_test() {
    std::cout << "\n=== Test: Stress Test ===" << std::endl;
    
    for (int round = 0; round < 10; round++) {
        YRX_COMPILER* compiler = nullptr;
        yrx_compiler_create(0, &compiler);
        
        for (int i = 0; i < 10; i++) {
            std::string rule = "rule stress_" + std::to_string(round) + "_" + std::to_string(i) + 
                              " { strings: $a = \"test\" condition: $a }";
            yrx_compiler_add_source(compiler, rule.c_str());
        }
        
        YRX_RULES* rules = yrx_compiler_build(compiler);
        yrx_compiler_destroy(compiler);
        
        if (rules) {
            YRX_SCANNER* scanner = nullptr;
            yrx_scanner_create(rules, &scanner);
            
            for (int i = 0; i < 100; i++) {
                const char* data = "test data";
                yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(data), strlen(data));
            }
            
            yrx_scanner_destroy(scanner);
            yrx_rules_destroy(rules);
        }
    }
    
    TEST_ASSERT(true, "Stress test completed: 10 rounds of compile/scan/destroy");
}
```

### 解读

**压力测试目的**：
- 验证长时间运行的稳定性
- 检测内存泄漏
- 确保资源正确释放

**测试覆盖**：
- 10 轮完整生命周期
- 每轮编译 10 条规则
- 每轮扫描 100 次

---

## 12. test_empty_data_scan - 空数据处理

```cpp
void test_empty_data_scan() {
    std::cout << "\n=== Test: Empty Data Scan ===" << std::endl;
    
    YRX_RULES* rules = nullptr;
    yrx_compile("rule test { condition: true }", &rules);
    
    if (rules) {
        YRX_SCANNER* scanner = nullptr;
        yrx_scanner_create(rules, &scanner);
        
        YRX_RESULT result = yrx_scanner_scan(scanner, nullptr, 0);
        TEST_ASSERT(result == YRX_SUCCESS, "Scan with null data and zero length");
        
        result = yrx_scanner_scan(scanner, reinterpret_cast<const uint8_t*>(""), 0);
        TEST_ASSERT(result == YRX_SUCCESS, "Scan with empty data");
        
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
    }
}
```

### 解读

**空数据扫描**：
- `nullptr, 0`：空指针和零长度
- `"", 0`：空字符串

**边界条件处理**：
- API 应该正确处理边界情况
- 不应该崩溃或产生未定义行为

---

## 13. API 函数总结

### 创建函数

| 函数 | 作用 |
|------|------|
| `yrx_compiler_create` | 创建编译器 |
| `yrx_compile` | 简化编译（一步到位） |
| `yrx_scanner_create` | 创建扫描器 |

### 销毁函数

| 函数 | 作用 |
|------|------|
| `yrx_compiler_destroy` | 销毁编译器 |
| `yrx_rules_destroy` | 销毁规则 |
| `yrx_scanner_destroy` | 销毁扫描器 |
| `yrx_buffer_destroy` | 销毁缓冲区 |

---

## 14. 内存管理最佳实践

### RAII 模式（推荐）

```cpp
class YaraRules {
public:
    YaraRules(const char* source) {
        yrx_compile(source, &rules_);
    }
    
    ~YaraRules() {
        if (rules_) {
            yrx_rules_destroy(rules_);
        }
    }
    
    YRX_RULES* get() const { return rules_; }
    
private:
    YRX_RULES* rules_ = nullptr;
};

class YaraScanner {
public:
    YaraScanner(YRX_RULES* rules) {
        yrx_scanner_create(rules, &scanner_);
    }
    
    ~YaraScanner() {
        if (scanner_) {
            yrx_scanner_destroy(scanner_);
        }
    }
    
    YRX_SCANNER* get() const { return scanner_; }
    
private:
    YRX_SCANNER* scanner_ = nullptr;
};
```

### 使用智能指针

```cpp
auto rules_deleter = [](YRX_RULES* r) { yrx_rules_destroy(r); };
std::unique_ptr<YRX_RULES, decltype(rules_deleter)> rules(nullptr, rules_deleter);
yrx_compile(source, &rules);
```

### 错误处理

```cpp
YRX_RULES* rules = nullptr;
YRX_RESULT result = yrx_compile(source, &rules);

if (result != YRX_SUCCESS || rules == nullptr) {
    // 处理错误
    const char* error = yrx_last_error();
    // ...
    return;
}

// 使用规则...

yrx_rules_destroy(rules);
```

---

## 15. 流程图

```
┌─────────────────────────────────────────────────────────────┐
│                    对象生命周期                              │
├─────────────────────────────────────────────────────────────┤
│  创建编译器                                                 │
│       ↓                                                     │
│  添加规则源码                                                │
│       ↓                                                     │
│  构建规则                                                   │
│       ↓                                                     │
│  销毁编译器（可选，编译后不再需要）                          │
│       ↓                                                     │
│  创建扫描器                                                 │
│       ↓                                                     │
│  执行扫描                                                   │
│       ↓                                                     │
│  销毁扫描器                                                 │
│       ↓                                                     │
│  销毁规则                                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 16. 注意事项

1. **销毁顺序**：
   - 先销毁依赖对象（扫描器）
   - 后销毁被依赖对象（规则）

2. **多线程**：
   - 规则可以多线程共享
   - 扫描器必须每个线程独立

3. **资源释放**：
   - 所有创建的对象都必须销毁
   - 使用 RAII 或智能指针管理

4. **错误检查**：
   - 检查返回值
   - 检查输出参数是否为 nullptr

5. **性能考虑**：
   - 复用扫描器比重复创建更高效
   - 大型规则集需要更多内存
