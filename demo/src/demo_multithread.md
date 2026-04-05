# demo_multithread.cpp 代码解读

本文档详细解读 `demo_multithread.cpp` 文件，面向不熟悉 C++ 语法和 YARA-X CAPI 接口的读者。

## 文件概述

这个文件演示了如何使用 YARA-X CAPI 库进行多线程扫描。它展示了：
- 规则编译
- 多线程扫描
- 回调函数使用
- 资源管理

---

## 1. 头文件引入

```cpp
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <cstring>
#include <chrono>
#include <atomic>

extern "C" {
#include "yara_x.h"
}
```

### 解读

| 头文件 | 用途 |
|--------|------|
| `<iostream>` | 标准输入输出流，用于 `std::cout` 和 `std::cerr` 打印信息 |
| `<vector>` | 动态数组容器，用于存储多个扫描器和测试数据 |
| `<thread>` | C++11 线程库，用于创建和管理线程 |
| `<mutex>` | 互斥锁，用于多线程环境下的同步 |
| `<string>` | 字符串类，方便字符串操作 |
| `<cstring>` | C 风格字符串操作函数 |
| `<chrono>` | 时间库，用于计时 |
| `<atomic>` | 原子操作，用于线程安全的计数器 |

**`extern "C"` 说明**：
- YARA-X CAPI 是用 C 语言编写的库
- C++ 和 C 有不同的函数名修饰规则
- `extern "C"` 告诉 C++ 编译器用 C 的方式处理这些函数声明
- 这样才能正确链接 CAPI 库中的函数

---

## 2. 全局变量

```cpp
std::mutex cout_mutex;
std::atomic<int> total_matches(0);
```

### 解读

**`std::mutex cout_mutex`**：
- 互斥锁，用于保护控制台输出
- 多个线程同时打印会导致输出混乱
- 使用锁确保同一时间只有一个线程能打印

**`std::atomic<int> total_matches(0)`**：
- 原子整数，用于统计所有线程的匹配总数
- `atomic` 确保多线程环境下的安全递增操作
- 初始值为 0

---

## 3. 规则回调函数

```cpp
void rule_callback(const YRX_RULE* rule, void* user_data) {
    const uint8_t* ident = nullptr;
    size_t len = 0;
    
    if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS) {
        std::string rule_name(reinterpret_cast<const char*>(ident), len);
        
        const uint8_t* ns = nullptr;
        size_t ns_len = 0;
        
        if (yrx_rule_namespace(rule, &ns, &ns_len) == YRX_SUCCESS) {
            std::string namespace_str(reinterpret_cast<const char*>(ns), ns_len);
            
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "[Thread " << std::this_thread::get_id() << "] "
                      << "Matched rule: " << namespace_str << ":" << rule_name << std::endl;
        }
    }
    
    int* matches = static_cast<int*>(user_data);
    (*matches)++;
}
```

### 解读

**函数签名**：
- `const YRX_RULE* rule`：指向匹配规则的指针，由 YARA-X 库提供
- `void* user_data`：用户自定义数据指针，用于传递额外信息

**API 函数说明**：

| 函数 | 参数 | 返回值 | 作用 |
|------|------|--------|------|
| `yrx_rule_identifier` | rule, &ident, &len | YRX_RESULT | 获取规则名称 |
| `yrx_rule_namespace` | rule, &ns, &ns_len | YRX_RESULT | 获取规则命名空间 |

**数据类型说明**：
- `uint8_t`：无符号 8 位整数，等同于 `unsigned char`
- `size_t`：无符号整数类型，用于表示大小和长度
- `const uint8_t*`：指向只读字节数组的指针

**C++ 语法说明**：

```cpp
std::string rule_name(reinterpret_cast<const char*>(ident), len);
```
- `reinterpret_cast`：C++ 类型转换操作符，将字节指针转为字符指针
- `std::string(ptr, len)`：从指针和长度构造字符串对象

```cpp
std::lock_guard<std::mutex> lock(cout_mutex);
```
- RAII 风格的锁管理
- 构造时自动加锁，析构时自动解锁
- 比手动 lock/unlock 更安全

```cpp
int* matches = static_cast<int*>(user_data);
```
- `static_cast`：C++ 类型转换操作符
- 将 `void*` 转换为 `int*`

---

## 4. 模式回调函数

```cpp
void pattern_callback(const YRX_PATTERN* pattern, void* user_data) {
    const uint8_t* ident = nullptr;
    size_t len = 0;
    
    if (yrx_pattern_identifier(pattern, &ident, &len) == YRX_SUCCESS) {
        std::string pattern_name(reinterpret_cast<const char*>(ident), len);
        
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "  Pattern: " << pattern_name << std::endl;
    }
    
    auto match_callback = [](const YRX_MATCH* match, void* user_data) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "    Match at offset " << match->offset 
                  << ", length " << match->length << std::endl;
    };
    
    yrx_pattern_iter_matches(pattern, match_callback, user_data);
}
```

### 解读

**Lambda 表达式说明**：

```cpp
auto match_callback = [](const YRX_MATCH* match, void* user_data) {
    // 函数体
};
```

- `[]`：捕获列表，空表示不捕获外部变量
- `(参数列表)`：与普通函数相同的参数声明
- `auto`：自动推导类型，编译器会推导为函数指针类型

**API 函数说明**：

| 函数 | 参数 | 作用 |
|------|------|------|
| `yrx_pattern_identifier` | pattern, &ident, &len | 获取模式名称（如 $a, $b） |
| `yrx_pattern_iter_matches` | pattern, callback, user_data | 迭代该模式的所有匹配 |

**YRX_MATCH 结构体**：
- `offset`：匹配在数据中的偏移位置（从 0 开始）
- `length`：匹配的长度

---

## 5. 扫描函数

```cpp
void scan_data(YRX_SCANNER* scanner, const std::string& data_name, 
               const std::vector<uint8_t>& data, int thread_id) {
    // ... 扫描逻辑
}

void scan_with_callback(YRX_SCANNER* scanner, const std::string& data_name,
                        const std::vector<uint8_t>& data, int thread_id) {
    // ... 带回调的扫描逻辑
}
```

### 解读

**参数说明**：

| 参数 | 类型 | 说明 |
|------|------|------|
| `scanner` | `YRX_SCANNER*` | 扫描器指针 |
| `data_name` | `const std::string&` | 数据名称（用于日志） |
| `data` | `const std::vector<uint8_t>&` | 要扫描的数据 |
| `thread_id` | `int` | 线程标识 |

**引用说明**：
- `const std::string&`：常量引用，避免拷贝，提高效率
- `const std::vector<uint8_t>&`：同上

**关键 API 调用**：

```cpp
yrx_scanner_on_matching_rule(scanner, rule_callback, &matches);
```
- 设置规则匹配时的回调函数
- `&matches` 是传递给回调的用户数据

```cpp
YRX_RESULT result = yrx_scanner_scan(scanner, data.data(), data.size());
```
- 执行扫描
- `data.data()`：获取 vector 内部数组指针
- `data.size()`：获取数据大小

---

## 6. main 函数 - YARA 规则定义

```cpp
const char* yara_rule = R"(
    rule test_rule_1 {
        meta:
            description = "Test rule for pattern matching"
            author = "Demo"
        strings:
            $a = "Hello" nocase
            $b = "World" nocase
        condition:
            $a or $b
    }
    
    // ... 更多规则
)";
```

### 解读

**原始字符串字面量**：
- `R"(...)"` 是 C++11 的原始字符串语法
- 括号内的内容不需要转义
- 适合嵌入多行文本（如 YARA 规则）

**YARA 规则结构**：

```
rule 规则名称 {
    meta:           // 元数据（可选）
        key = value
    strings:        // 定义字符串模式
        $名称 = "模式" 修饰符
    condition:      // 匹配条件
        表达式
}
```

**规则说明**：

| 规则 | 模式类型 | 条件 | 匹配内容 |
|------|----------|------|----------|
| test_rule_1 | 字符串 "Hello"/"World" | $a or $b | 包含 Hello 或 World |
| test_rule_2 | 十六进制 {48 65 6C 6C 6F} | $hex | 包含 "Hello" 的十六进制表示 |
| test_rule_3 | 正则 /test.*pattern/i | $regex | 包含 test...pattern（不区分大小写） |
| always_match | 无 | true | 始终匹配 |

**修饰符说明**：
- `nocase`：不区分大小写
- `i`（正则中）：不区分大小写

---

## 7. 规则编译流程

```cpp
// 1. 创建编译器
YRX_COMPILER* compiler = nullptr;
YRX_RESULT result = yrx_compiler_create(0, &compiler);

// 2. 添加源代码
result = yrx_compiler_add_source(compiler, yara_rule);

// 3. 构建规则
YRX_RULES* rules = yrx_compiler_build(compiler);

// 4. 销毁编译器（规则已构建，编译器不再需要）
yrx_compiler_destroy(compiler);
```

### 解读

**编译流程图**：

```
创建编译器 → 添加源代码 → 构建规则 → 销毁编译器
     ↓              ↓           ↓
 yrx_compiler_   yrx_compiler_  yrx_compiler_
 create          add_source    build
```

**API 函数说明**：

| 函数 | 参数 | 返回值 | 作用 |
|------|------|--------|------|
| `yrx_compiler_create` | flags, &compiler | YRX_RESULT | 创建编译器 |
| `yrx_compiler_add_source` | compiler, source | YRX_RESULT | 添加 YARA 源代码 |
| `yrx_compiler_build` | compiler | YRX_RULES* | 构建编译后的规则 |
| `yrx_compiler_destroy` | compiler | void | 销毁编译器 |

**返回值检查**：
- `YRX_SUCCESS`：操作成功
- 其他值：操作失败，可用 `yrx_last_error()` 获取错误信息

---

## 8. 创建扫描器

```cpp
const int num_threads = 4;
std::vector<YRX_SCANNER*> scanners(num_threads);

for (int i = 0; i < num_threads; i++) {
    result = yrx_scanner_create(rules, &scanners[i]);
    // ...
}
```

### 解读

**为什么需要多个扫描器？**
- 每个扫描器只能在单个线程中使用
- 多线程扫描需要每个线程有独立的扫描器
- 规则（YRX_RULES）可以共享，扫描器不能共享

**std::vector 说明**：
- `std::vector<YRX_SCANNER*> scanners(num_threads)`：创建包含 4 个元素的 vector
- 每个元素是 `YRX_SCANNER*` 类型的指针

---

## 9. 准备测试数据

```cpp
std::vector<std::vector<uint8_t>> test_data = {
    std::vector<uint8_t>(std::begin("Hello World!"), std::end("Hello World!")),
    // ...
};
```

### 解读

**嵌套 vector**：
- `std::vector<std::vector<uint8_t>>`：二维动态数组
- 外层 vector 存储多个数据块
- 每个数据块是 `std::vector<uint8_t>`

**字符串转 vector**：
```cpp
std::vector<uint8_t>(std::begin("Hello World!"), std::end("Hello World!"))
```
- `std::begin/end`：获取数组的开始和结束迭代器
- 用迭代器范围构造 vector

---

## 10. 多线程扫描

```cpp
auto start_time = std::chrono::high_resolution_clock::now();

std::vector<std::thread> threads;

for (int i = 0; i < num_threads; i++) {
    threads.emplace_back(scan_with_callback, scanners[i], 
                        std::ref(data_names[i]), std::ref(test_data[i]), i);
}

for (auto& thread : threads) {
    thread.join();
}

auto end_time = std::chrono::high_resolution_clock::now();
```

### 解读

**创建线程**：

```cpp
threads.emplace_back(scan_with_callback, scanners[i], 
                    std::ref(data_names[i]), std::ref(test_data[i]), i);
```
- `emplace_back`：在 vector 末尾原地构造元素
- 第一个参数是线程函数
- 后续参数传递给线程函数

**std::ref 说明**：
- `std::ref`：创建引用包装器
- 线程函数参数默认是拷贝传递
- 使用 `std::ref` 可以传递引用

**等待线程完成**：

```cpp
for (auto& thread : threads) {
    thread.join();
}
```
- `join()`：阻塞等待线程完成
- 必须调用 `join()` 或 `detach()`
- 否则程序会在析构时终止

**计时**：
- `std::chrono::high_resolution_clock`：高精度时钟
- `duration_cast<std::chrono::milliseconds>`：转换为毫秒

---

## 11. 扫描器复用

```cpp
std::vector<uint8_t> additional_data(...);

int additional_matches = 0;
yrx_scanner_on_matching_rule(scanners[0], rule_callback, &additional_matches);

result = yrx_scanner_scan(scanners[0], additional_data.data(), additional_data.size());
```

### 解读

**扫描器复用的好处**：
- 避免重复创建/销毁的开销
- 适合需要多次扫描的场景

**注意**：
- 每次扫描前可以重新设置回调
- 扫描器会保持之前的状态

---

## 12. 超时功能

```cpp
YRX_SCANNER* timeout_scanner = nullptr;
result = yrx_scanner_create(rules, &timeout_scanner);

if (result == YRX_SUCCESS) {
    yrx_scanner_set_timeout(timeout_scanner, 1);  // 1 秒超时
    // ...
}
```

### 解读

**超时设置**：
- `yrx_scanner_set_timeout(scanner, seconds)`：设置扫描超时时间
- 单位是秒
- 超时后扫描会被中断

---

## 13. 资源清理

```cpp
// 先销毁扫描器
for (int i = 0; i < num_threads; i++) {
    yrx_scanner_destroy(scanners[i]);
}

// 再销毁规则
yrx_rules_destroy(rules);
```

### 解读

**销毁顺序很重要**：
1. 先销毁所有扫描器
2. 再销毁规则

**原因**：
- 扫描器依赖规则存在
- 如果先销毁规则，扫描器会访问无效内存

---

## 14. 完整流程图

```
┌─────────────────────────────────────────────────────────────┐
│                        主线程                                │
├─────────────────────────────────────────────────────────────┤
│  1. 创建编译器 (yrx_compiler_create)                        │
│  2. 添加源代码 (yrx_compiler_add_source)                    │
│  3. 构建规则 (yrx_compiler_build)                           │
│  4. 销毁编译器 (yrx_compiler_destroy)                       │
│  5. 创建多个扫描器 (yrx_scanner_create × N)                 │
│  6. 准备测试数据                                            │
│  7. 启动多线程扫描                                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     工作线程 1..N                            │
├─────────────────────────────────────────────────────────────┤
│  设置回调 (yrx_scanner_on_matching_rule)                    │
│  执行扫描 (yrx_scanner_scan)                                │
│  回调函数被调用（规则匹配时）                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        清理阶段                             │
├─────────────────────────────────────────────────────────────┤
│  1. 销毁所有扫描器 (yrx_scanner_destroy × N)                │
│  2. 销毁规则 (yrx_rules_destroy)                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 15. 关键要点总结

| 概念 | 说明 |
|------|------|
| 线程安全 | YRX_RULES 可共享，YRX_SCANNER 每线程一个 |
| 回调函数 | 用于处理匹配结果，必须线程安全 |
| 资源管理 | 先销毁扫描器，再销毁规则 |
| 错误处理 | 检查 YRX_RESULT，用 yrx_last_error() 获取详情 |
| 互斥锁 | 保护共享资源（如控制台输出） |
| 原子变量 | 线程安全的计数器 |

---

## 16. 常见问题

### Q: 为什么使用 `extern "C"`？
A: YARA-X CAPI 是 C 语言库，C++ 需要用 `extern "C"` 来正确链接。

### Q: `std::lock_guard` 是什么？
A: RAII 风格的锁管理器，构造时加锁，析构时自动解锁，比手动管理更安全。

### Q: 为什么每个线程需要独立的扫描器？
A: 扫描器不是线程安全的，内部有状态，多线程共享会导致数据竞争。

### Q: `reinterpret_cast` 和 `static_cast` 有什么区别？
A: `reinterpret_cast` 是低级别的位重新解释，`static_cast` 是有类型检查的转换。
