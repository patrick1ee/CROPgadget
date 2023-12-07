CC = gcc
CFLAGS = -fno-stack-protector -m32 -static
SRC_DIR = sources
BIN_DIR = binaries

# Find all C files in the source directory
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Generate corresponding output file names
BINS = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%-32, $(SRCS))

# Target to build all programs
all: $(BINS)

# Rule to compile C source files to executable files
$(BIN_DIR)/%-32: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@

# Clean rule to remove compiled files
clean:
	rm -f $(BIN_DIR)/*

# PHONY target to prevent conflicts with file names
.PHONY: all clean