# YARA-X CAPI Demo and Test Makefile
# This Makefile builds the demo programs and test suites with the yara-x-capi library

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -pthread

# Directory structure
SRC_DIR = src
INC_DIR = include
LIB_DIR = lib
BIN_DIR = bin
TEST_DIR = tests

# Library settings
LDFLAGS = -L$(LIB_DIR) -lyara_x_capi -ldl -lpthread -lm -Wl,-rpath,'$$ORIGIN/../lib'
INCLUDES = -I$(INC_DIR)

# Demo targets
DEMO_TARGET = $(BIN_DIR)/demo_multithread
DEMO_SOURCES = $(SRC_DIR)/demo_multithread.cpp

# Test targets
TEST_TARGETS = \
	$(BIN_DIR)/test_basic_compile \
	$(BIN_DIR)/test_patterns \
	$(BIN_DIR)/test_metadata \
	$(BIN_DIR)/test_globals \
	$(BIN_DIR)/test_serialization \
	$(BIN_DIR)/test_error_handling \
	$(BIN_DIR)/test_memory \
	$(BIN_DIR)/test_rules_load \
	$(BIN_DIR)/test_rules_category \
	$(BIN_DIR)/test_performance \
	$(BIN_DIR)/test_functionality \
	$(BIN_DIR)/test_edge_cases

# Test sources
TEST_BASIC_COMPILE_SRC = $(SRC_DIR)/test_basic_compile.cpp
TEST_PATTERNS_SRC = $(SRC_DIR)/test_patterns.cpp
TEST_METADATA_SRC = $(SRC_DIR)/test_metadata.cpp
TEST_GLOBALS_SRC = $(SRC_DIR)/test_globals.cpp
TEST_SERIALIZATION_SRC = $(SRC_DIR)/test_serialization.cpp
TEST_ERROR_HANDLING_SRC = $(SRC_DIR)/test_error_handling.cpp
TEST_MEMORY_SRC = $(SRC_DIR)/test_memory.cpp
TEST_RULES_LOAD_SRC = $(SRC_DIR)/test_rules_load.cpp
TEST_RULES_CATEGORY_SRC = $(SRC_DIR)/test_rules_category.cpp
TEST_PERFORMANCE_SRC = $(SRC_DIR)/test_performance.cpp
TEST_FUNCTIONALITY_SRC = $(SRC_DIR)/test_functionality.cpp
TEST_EDGE_CASES_SRC = $(SRC_DIR)/test_edge_cases.cpp

# Default target
all: $(BIN_DIR) $(DEMO_TARGET) $(TEST_TARGETS)
	@echo ""
	@echo "Build complete! Available targets:"
	@echo "  Demo: $(DEMO_TARGET)"
	@echo "  Tests: $(TEST_TARGETS)"
	@echo ""
	@echo "Run 'make test' to execute all tests"

# Create bin directory
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build demo
$(DEMO_TARGET): $(DEMO_SOURCES) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)
	@echo "Built demo: $@"

# Build individual tests
$(BIN_DIR)/test_basic_compile: $(TEST_BASIC_COMPILE_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_patterns: $(TEST_PATTERNS_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_metadata: $(TEST_METADATA_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_globals: $(TEST_GLOBALS_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_serialization: $(TEST_SERIALIZATION_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_error_handling: $(TEST_ERROR_HANDLING_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_memory: $(TEST_MEMORY_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_rules_load: $(TEST_RULES_LOAD_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_rules_category: $(TEST_RULES_CATEGORY_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_performance: $(TEST_PERFORMANCE_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_functionality: $(TEST_FUNCTIONALITY_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/test_edge_cases: $(TEST_EDGE_CASES_SRC) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

# Run all tests
test: $(TEST_TARGETS)
	@echo ""
	@echo "========================================"
	@echo "  Running YARA-X CAPI Test Suite"
	@echo "========================================"
	@total_passed=0; \
	total_failed=0; \
	for test in $(TEST_TARGETS); do \
		echo ""; \
		echo "Running: $$test"; \
		echo "----------------------------------------"; \
		if $$test; then \
			echo "Test $$test PASSED"; \
		else \
			echo "Test $$test FAILED"; \
			total_failed=$$((total_failed + 1)); \
		fi; \
	done; \
	echo ""; \
	echo "========================================"; \
	echo "  Test Suite Summary"; \
	echo "========================================"; \
	if [ $$total_failed -eq 0 ]; then \
		echo "  All tests PASSED!"; \
	else \
		echo "  $$total_failed test(s) FAILED"; \
	fi; \
	exit $$total_failed

# Run individual tests
test-basic: $(BIN_DIR)/test_basic_compile
	./$(BIN_DIR)/test_basic_compile

test-patterns: $(BIN_DIR)/test_patterns
	./$(BIN_DIR)/test_patterns

test-metadata: $(BIN_DIR)/test_metadata
	./$(BIN_DIR)/test_metadata

test-globals: $(BIN_DIR)/test_globals
	./$(BIN_DIR)/test_globals

test-serialization: $(BIN_DIR)/test_serialization
	./$(BIN_DIR)/test_serialization

test-error: $(BIN_DIR)/test_error_handling
	./$(BIN_DIR)/test_error_handling

test-memory: $(BIN_DIR)/test_memory
	./$(BIN_DIR)/test_memory

test-rules-load: $(BIN_DIR)/test_rules_load
	./$(BIN_DIR)/test_rules_load

test-rules-category: $(BIN_DIR)/test_rules_category
	./$(BIN_DIR)/test_rules_category

test-performance: $(BIN_DIR)/test_performance
	./$(BIN_DIR)/test_performance

test-functionality: $(BIN_DIR)/test_functionality
	./$(BIN_DIR)/test_functionality

test-edge-cases: $(BIN_DIR)/test_edge_cases
	./$(BIN_DIR)/test_edge_cases

# Run demo
run: $(DEMO_TARGET)
	./$(DEMO_TARGET)

# Clean build artifacts
clean:
	rm -f $(BIN_DIR)/*
	@echo "Cleaned build artifacts"

# Clean all including test data
clean-all: clean
	rm -f $(TEST_DIR)/data/serialized_rules.bin
	@echo "Cleaned all artifacts"

# Show directory structure
show-structure:
	@echo "Demo directory structure:"
	@find . -type f \( -name "*.cpp" -o -name "*.h" -o -name "*.so*" -o -name "*.a" -o -name "Makefile" -o -name "*.md" -o -name "*.yar" -o -name "*.txt" \) | sort

# Help
help:
	@echo "YARA-X CAPI Demo and Test Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build demo and all tests (default)"
	@echo "  test             - Run all tests"
	@echo "  test-basic       - Run basic compile tests"
	@echo "  test-patterns    - Run pattern matching tests"
	@echo "  test-metadata    - Run metadata tests"
	@echo "  test-globals     - Run global variables tests"
	@echo "  test-serialization - Run serialization tests"
	@echo "  test-error       - Run error handling tests"
	@echo "  test-memory      - Run memory management tests"
	@echo "  test-rules-load  - Run rules load and compilation tests"
	@echo "  test-rules-category - Run rules category tests"
	@echo "  test-performance - Run performance tests"
	@echo "  test-functionality - Run functionality tests"
	@echo "  test-edge-cases - Run edge cases tests"
	@echo "  run              - Build and run the demo"
	@echo "  clean            - Remove build artifacts"
	@echo "  clean-all        - Remove all generated files"
	@echo "  show-structure   - Display the directory structure"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Directory structure:"
	@echo "  src/             - Source code"
	@echo "  include/         - Header files"
	@echo "  lib/             - Library files (.so, .a)"
	@echo "  bin/             - Compiled executables"
	@echo "  tests/rules/     - Test YARA rule files"
	@echo "  tests/data/      - Test data files"

.PHONY: all test test-basic test-patterns test-metadata test-globals test-serialization test-error test-memory test-rules-load test-rules-category test-performance test-functionality test-edge-cases run clean clean-all show-structure help
