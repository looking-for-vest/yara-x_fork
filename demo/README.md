# YARA-X CAPI Multi-threaded Demo

This demo demonstrates how to use the YARA-X CAPI library in C++ with multi-threading support.

## Features Demonstrated

1. **Rule Compilation**: Compile YARA rules from source code
2. **Multi-threaded Scanning**: Use multiple scanners in parallel threads
3. **Scanner Reuse**: Reuse the same scanner for multiple scans
4. **Callback Functions**: Handle matching rules with custom callbacks
5. **Timeout Support**: Set scan timeouts to prevent long-running scans
6. **Thread Safety**: Demonstrate thread-safe usage patterns
7. **Comprehensive Test Suite**: Validate all major CAPI functionality

## Building the Demo

### Prerequisites

- C++17 compatible compiler (g++ recommended)
- YARA-X CAPI library built with `cargo cbuild --package yara-x-capi --release`
- pthread library

### Compilation

```bash
make
```

This will compile the demo program and all test cases using the Makefile.

## Running the Demo

```bash
make run
```

Or directly:

```bash
./bin/demo_multithread
```

## Running the Test Suite

```bash
make test
```

This will run all test cases and show the results.

## Demo Output Explanation

The demo performs the following steps:

1. **Compiling YARA Rules**: Creates 4 test rules including:
   - String pattern matching (case-insensitive)
   - Hex pattern matching
   - Regex pattern matching
   - Always-matching rule

2. **Creating Scanners**: Creates 4 separate scanners from the compiled rules

3. **Multi-threaded Scanning**: Uses 4 threads to scan different data simultaneously:
   - data1.txt: "Hello World!" (matches test_rule_1, test_rule_2, always_match)
   - data2.txt: "This is a test pattern for YARA" (matches test_rule_3, always_match)
   - data3.txt: "Random data without matches" (matches only always_match)
   - data4.txt: "HELLO from another thread" (matches test_rule_1, always_match)

4. **Scanner Reuse**: Demonstrates reusing a scanner for additional data

5. **Timeout Functionality**: Shows how to create a scanner with timeout

6. **Cleanup**: Properly destroys all resources

## Test Suite

The demo includes a comprehensive test suite that validates all major YARA-X CAPI functionality:

### Test Modules

1. **test_basic_compile.cpp**
   - Basic rule compilation
   - Compiler lifecycle
   - Multi-rule compilation
   - Namespaces
   - File loading and includes

2. **test_patterns.cpp**
   - String patterns (case-insensitive, wide, fullword)
   - Hex patterns (with jumps and wildcards)
   - Regex patterns
   - Pattern matching conditions

3. **test_metadata.cpp**
   - String, integer, float, and boolean metadata
   - Metadata iteration
   - Tags

4. **test_globals.cpp**
   - Global variables (bool, int, float, string, JSON)
   - Scanner-level global variables

5. **test_serialization.cpp**
   - Rule serialization and deserialization
   - Metadata preservation
   - Large rule sets

6. **test_error_handling.cpp**
   - Syntax errors
   - Unknown identifiers
   - Invalid arguments
   - Error message retrieval
   - JSON error output

7. **test_memory.cpp**
   - Resource lifecycle management
   - Multi-threaded scanning
   - Stress testing
   - Memory usage

8. **test_integration.cpp**
   - Malware sample scanning
   - Malicious document scanning
   - WebShell sample scanning
   - Real-world rule testing

### Test Results

The test suite runs 172 test cases covering all major CAPI functionality, ensuring the library is working correctly for integration into other C++ projects.

## Key API Concepts

### Thread Safety Model

- **YRX_RULES**: Thread-safe for read operations, can be shared across multiple scanners
- **YRX_SCANNER**: Each scanner can be used in a separate thread, but individual scanners are not thread-safe
- **Callbacks**: Must be thread-safe if they access shared resources

### Resource Management

1. Always destroy scanners before destroying rules
2. Use `yrx_last_error()` to get error messages after failed operations
3. Check return codes (YRX_SUCCESS) for all API calls

### Multi-threading Best Practices

1. **Shared Rules**: Create rules once, share across multiple scanners
2. **Per-thread Scanners**: Each thread should have its own scanner
3. **Thread-safe Callbacks**: Use mutexes when accessing shared resources in callbacks
4. **Resource Cleanup**: Ensure proper cleanup order (scanners before rules)

## Code Structure

### Main Components

- `rule_callback()`: Called when a rule matches during scanning
- `pattern_callback()`: Called for each pattern in a matching rule
- `scan_data()`: Basic scanning function without callbacks
- `scan_with_callback()`: Scanning function with callback support
- `main()`: Orchestrates the entire demo

### Thread Safety

The demo uses:
- `std::mutex` for thread-safe console output
- `std::atomic<int>` for thread-safe match counting
- Separate scanners for each thread

## API Functions Used

### Compilation
- `yrx_compiler_create()`: Create a compiler
- `yrx_compiler_add_source()`: Add YARA source code
- `yrx_compiler_build()`: Build compiled rules
- `yrx_compiler_destroy()`: Destroy compiler

### Rules Management
- `yrx_rules_count()`: Get number of rules
- `yrx_rules_destroy()`: Destroy rules
- `yrx_rules_serialize()`: Serialize rules to buffer
- `yrx_rules_deserialize()`: Deserialize rules from buffer

### Scanner Operations
- `yrx_scanner_create()`: Create a scanner from rules
- `yrx_scanner_scan()`: Scan data buffer
- `yrx_scanner_on_matching_rule()`: Set callback for matching rules
- `yrx_scanner_set_timeout()`: Set scan timeout
- `yrx_scanner_destroy()`: Destroy scanner

### Rule Information
- `yrx_rule_identifier()`: Get rule name
- `yrx_rule_namespace()`: Get rule namespace
- `yrx_rule_iter_patterns()`: Iterate over patterns in a rule
- `yrx_rule_iter_metadata()`: Iterate over metadata in a rule
- `yrx_rule_iter_tags()`: Iterate over tags in a rule

### Pattern Information
- `yrx_pattern_identifier()`: Get pattern name
- `yrx_pattern_iter_matches()`: Iterate over pattern matches

### Global Variables
- `yrx_compiler_define_global_bool()`: Define boolean global variable
- `yrx_compiler_define_global_int()`: Define integer global variable
- `yrx_compiler_define_global_float()`: Define float global variable
- `yrx_compiler_define_global_string()`: Define string global variable
- `yrx_compiler_define_global_json()`: Define JSON global variable
- `yrx_scanner_set_global_bool()`: Set scanner-level boolean global
- `yrx_scanner_set_global_int()`: Set scanner-level integer global
- `yrx_scanner_set_global_float()`: Set scanner-level float global
- `yrx_scanner_set_global_string()`: Set scanner-level string global

### Error Handling
- `yrx_last_error()`: Get last error message
- `yrx_compiler_errors_json()`: Get compiler errors as JSON
- `yrx_compiler_warnings_json()`: Get compiler warnings as JSON

## Makefile Details

The Makefile includes:
- Proper library paths and includes
- Runtime library path (rpath) for easy execution
- Clean and run targets
- Test targets for all test cases
- All necessary dependencies (pthread, dl, m)

## Troubleshooting

### Library Not Found Error

If you get "error while loading shared libraries: libyara_x_capi.so.1", ensure:

1. The library exists in the expected location
2. Create a symlink: `ln -sf libyara_x_capi.so libyara_x_capi.so.1`
3. Or use LD_LIBRARY_PATH: `LD_LIBRARY_PATH=/path/to/library ./demo_multithread`

### Compilation Errors

Ensure:
- C++17 support is enabled
- All include paths are correct
- Library paths point to the correct location

## Performance Considerations

- Each scanner maintains its own state, so memory usage scales with the number of scanners
- For high-throughput scenarios, consider reusing scanners
- The demo shows minimal overhead for multi-threaded scanning
- Actual performance depends on rule complexity and data size

## Extension Ideas

1. Add file scanning with `yrx_scanner_scan_file()`
2. Implement block scanning for large files
3. Add rule serialization/deserialization (already tested)
4. Implement custom metadata handling (already tested)
5. Add module support (PE, ELF, etc.)
6. Implement profiling with `yrx_scanner_iter_slowest_rules()`

## License

This demo is provided as-is for educational purposes to demonstrate YARA-X CAPI usage.
