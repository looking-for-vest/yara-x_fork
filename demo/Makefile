# YARA-X CAPI Multi-threaded Demo Makefile
# This Makefile builds the demo program with the yara-x-capi library

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -pthread

# Directory structure
SRC_DIR = src
INC_DIR = include
LIB_DIR = lib
BIN_DIR = bin

# Target executable
TARGET = $(BIN_DIR)/demo_multithread
SOURCES = $(SRC_DIR)/demo_multithread.cpp

# Library settings
LDFLAGS = -L$(LIB_DIR) -lyara_x_capi -ldl -lpthread -lm -Wl,-rpath,'$$ORIGIN/../lib'
INCLUDES = -I$(INC_DIR)

# Default target
all: $(TARGET)

# Create bin directory if it doesn't exist and build the target
$(TARGET): $(SOURCES) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCES) $(LDFLAGS)
	@echo "Build successful! Executable: $(TARGET)"

# Create bin directory
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean build artifacts
clean:
	rm -f $(TARGET)
	@echo "Cleaned build artifacts"

# Run the demo
run: $(TARGET)
	./$(TARGET)

# Show directory structure
show-structure:
	@echo "Demo directory structure:"
	@find . -type f -name "*.cpp" -o -name "*.h" -o -name "*.so*" -o -name "*.a" -o -name "Makefile" -o -name "*.md" | sort

# Help
help:
	@echo "YARA-X CAPI Demo Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Build the demo program (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run the demo"
	@echo "  show-structure - Display the directory structure"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Directory structure:"
	@echo "  src/         - Source code"
	@echo "  include/     - Header files"
	@echo "  lib/         - Library files (.so, .a)"
	@echo "  bin/         - Compiled executable"

.PHONY: all clean run show-structure help
