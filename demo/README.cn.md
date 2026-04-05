# YARA-X CAPI 多线程演示

本演示展示了如何在 C++ 中使用支持多线程的 YARA-X CAPI 库。

## 演示功能

1. **规则编译**：从源代码编译 YARA 规则
2. **多线程扫描**：在并行线程中使用多个扫描器
3. **扫描器复用**：重复使用同一个扫描器进行多次扫描
4. **回调函数**：使用自定义回调处理匹配的规则
5. **超时支持**：设置扫描超时以防止长时间运行的扫描
6. **线程安全**：演示线程安全的使用模式
7. **完整测试套件**：验证所有主要 CAPI 功能

## 构建演示程序

### 前置条件

- C++17 兼容编译器（推荐使用 g++）
- 使用 `cargo cbuild --package yara-x-capi --release` 构建的 YARA-X CAPI 库
- pthread 库

### 编译

```bash
make
```

这将使用 Makefile 编译演示程序和所有测试用例。

## 运行演示程序

```bash
make run
```

或直接运行：

```bash
./bin/demo_multithread
```

## 运行测试套件

```bash
make test
```

这将运行所有测试用例并显示结果。

## 演示输出说明

演示程序执行以下步骤：

1. **编译 YARA 规则**：创建 4 条测试规则，包括：
   - 字符串模式匹配（不区分大小写）
   - 十六进制模式匹配
   - 正则表达式模式匹配
   - 始终匹配的规则

2. **创建扫描器**：从编译后的规则创建 4 个独立的扫描器

3. **多线程扫描**：使用 4 个线程同时扫描不同的数据：
   - data1.txt: "Hello World!"（匹配 test_rule_1, test_rule_2, always_match）
   - data2.txt: "This is a test pattern for YARA"（匹配 test_rule_3, always_match）
   - data3.txt: "Random data without matches"（仅匹配 always_match）
   - data4.txt: "HELLO from another thread"（匹配 test_rule_1, always_match）

4. **扫描器复用**：演示复用扫描器扫描额外数据

5. **超时功能**：展示如何创建带超时的扫描器

6. **资源清理**：正确销毁所有资源

## 测试套件

演示程序包含一个完整的测试套件，验证所有主要的 YARA-X CAPI 功能：

### 测试模块

1. **test_basic_compile.cpp**
   - 基本规则编译
   - 编译器生命周期
   - 多规则编译
   - 命名空间
   - 文件加载和包含

2. **test_patterns.cpp**
   - 字符串模式（不区分大小写、宽字符、全词匹配）
   - 十六进制模式（带跳转和通配符）
   - 正则表达式模式
   - 模式匹配条件

3. **test_metadata.cpp**
   - 字符串、整数、浮点数和布尔类型元数据
   - 元数据迭代
   - 标签

4. **test_globals.cpp**
   - 全局变量（bool、int、float、string、JSON）
   - 扫描器级别的全局变量

5. **test_serialization.cpp**
   - 规则序列化和反序列化
   - 元数据保留
   - 大型规则集

6. **test_error_handling.cpp**
   - 语法错误
   - 未知标识符
   - 无效参数
   - 错误消息获取
   - JSON 错误输出

7. **test_memory.cpp**
   - 资源生命周期管理
   - 多线程扫描
   - 压力测试
   - 内存使用

### 测试结果

测试套件运行 172 个测试用例，覆盖所有主要 CAPI 功能，确保库能正确工作以便集成到其他 C++ 项目中。

## 关键 API 概念

### 线程安全模型

- **YRX_RULES**：读操作线程安全，可在多个扫描器之间共享
- **YRX_SCANNER**：每个扫描器可在独立线程中使用，但单个扫描器本身不是线程安全的
- **回调函数**：如果访问共享资源，必须是线程安全的

### 资源管理

1. 始终在销毁规则之前销毁扫描器
2. 使用 `yrx_last_error()` 获取失败操作后的错误消息
3. 检查所有 API 调用的返回码（YRX_SUCCESS）

### 多线程最佳实践

1. **共享规则**：创建一次规则，在多个扫描器之间共享
2. **每线程扫描器**：每个线程应有自己的扫描器
3. **线程安全回调**：在回调中访问共享资源时使用互斥锁
4. **资源清理**：确保正确的清理顺序（扫描器先于规则）

## 代码结构

### 主要组件

- `rule_callback()`：扫描时规则匹配时调用
- `pattern_callback()`：匹配规则中的每个模式时调用
- `scan_data()`：不带回调的基本扫描函数
- `scan_with_callback()`：带回调支持的扫描函数
- `main()`：协调整个演示程序

### 线程安全

演示程序使用：
- `std::mutex` 用于线程安全的控制台输出
- `std::atomic<int>` 用于线程安全的匹配计数
- 每个线程独立的扫描器

## 使用的 API 函数

### 编译
- `yrx_compiler_create()`：创建编译器
- `yrx_compiler_add_source()`：添加 YARA 源代码
- `yrx_compiler_build()`：构建编译后的规则
- `yrx_compiler_destroy()`：销毁编译器

### 规则管理
- `yrx_rules_count()`：获取规则数量
- `yrx_rules_destroy()`：销毁规则
- `yrx_rules_serialize()`：将规则序列化到缓冲区
- `yrx_rules_deserialize()`：从缓冲区反序列化规则

### 扫描器操作
- `yrx_scanner_create()`：从规则创建扫描器
- `yrx_scanner_scan()`：扫描数据缓冲区
- `yrx_scanner_on_matching_rule()`：设置匹配规则的回调
- `yrx_scanner_set_timeout()`：设置扫描超时
- `yrx_scanner_destroy()`：销毁扫描器

### 规则信息
- `yrx_rule_identifier()`：获取规则名称
- `yrx_rule_namespace()`：获取规则命名空间
- `yrx_rule_iter_patterns()`：迭代规则中的模式
- `yrx_rule_iter_metadata()`：迭代规则中的元数据
- `yrx_rule_iter_tags()`：迭代规则中的标签

### 模式信息
- `yrx_pattern_identifier()`：获取模式名称
- `yrx_pattern_iter_matches()`：迭代模式匹配

### 全局变量
- `yrx_compiler_define_global_bool()`：定义布尔类型全局变量
- `yrx_compiler_define_global_int()`：定义整数类型全局变量
- `yrx_compiler_define_global_float()`：定义浮点类型全局变量
- `yrx_compiler_define_global_string()`：定义字符串类型全局变量
- `yrx_compiler_define_global_json()`：定义 JSON 类型全局变量
- `yrx_scanner_set_global_bool()`：设置扫描器级别的布尔全局变量
- `yrx_scanner_set_global_int()`：设置扫描器级别的整数全局变量
- `yrx_scanner_set_global_float()`：设置扫描器级别的浮点全局变量
- `yrx_scanner_set_global_string()`：设置扫描器级别的字符串全局变量

### 错误处理
- `yrx_last_error()`：获取最后的错误消息
- `yrx_compiler_errors_json()`：以 JSON 格式获取编译器错误
- `yrx_compiler_warnings_json()`：以 JSON 格式获取编译器警告

## Makefile 详情

Makefile 包含：
- 正确的库路径和包含路径
- 运行时库路径（rpath）以便于执行
- 清理和运行目标
- 所有测试用例的测试目标
- 所有必要的依赖项（pthread、dl、m）

## 故障排除

### 找不到库错误

如果遇到 "error while loading shared libraries: libyara_x_capi.so.1"，请确保：

1. 库存在于预期位置
2. 创建符号链接：`ln -sf libyara_x_capi.so libyara_x_capi.so.1`
3. 或使用 LD_LIBRARY_PATH：`LD_LIBRARY_PATH=/path/to/library ./demo_multithread`

### 编译错误

请确保：
- 已启用 C++17 支持
- 所有包含路径正确
- 库路径指向正确位置

## 性能考虑

- 每个扫描器维护自己的状态，因此内存使用量随扫描器数量增加
- 对于高吞吐量场景，考虑复用扫描器
- 演示程序显示多线程扫描的开销很小
- 实际性能取决于规则复杂性和数据大小

## 扩展思路

1. 使用 `yrx_scanner_scan_file()` 添加文件扫描
2. 为大文件实现块扫描
3. 添加规则序列化/反序列化（已测试）
4. 实现自定义元数据处理（已测试）
5. 添加模块支持（PE、ELF 等）
6. 使用 `yrx_scanner_iter_slowest_rules()` 实现性能分析

## 许可证

本演示程序按原样提供，用于教育目的，展示 YARA-X CAPI 的使用方法。
