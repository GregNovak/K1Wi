# ============================================================
# OPUS Build System
# ============================================================
# Targets:
#   make debug
#   make release
#   make sanitize
#   make tsan
#   make valgrind
#   make clean
# ============================================================

# ------------------------------------------------------------
# Compiler
# ------------------------------------------------------------
CC := clang

# ------------------------------------------------------------
# Project Structure
# ------------------------------------------------------------
SRC_DIR := .
INC_DIR := include
OBJ_DIR := build
BIN_DIR := bin

TARGET := $(BIN_DIR)/opus

# ------------------------------------------------------------
# Source Discovery
# ------------------------------------------------------------
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

# ------------------------------------------------------------
# Libraries
# ------------------------------------------------------------
LIBS := -lgmp -lpthread -lm -lncurses -ljpeg -lcrypto

# -----------------------------------------------------------
# Base Compiler Flags
# ------------------------------------------------------------
BASE_CFLAGS := \
	-std=c11 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wshadow \
	-Wconversion \
	-Wformat=2 \
	-Wnull-dereference \
	-Wdouble-promotion \
	-Wstrict-prototypes \
	-MMD \
	-MP \
	-I$(INC_DIR)

# ------------------------------------------------------------
# Build Modes
# ------------------------------------------------------------
DEBUG_FLAGS := -O0 -g

RELEASE_FLAGS := \
	-O2 \
	-DNDEBUG

SANITIZER_FLAGS := \
	-fsanitize=address,undefined

THREAD_SANITIZER_FLAGS := \
	-fsanitize=thread

# ------------------------------------------------------------
# Default Target
# ------------------------------------------------------------
all: debug

# ------------------------------------------------------------
# Debug Build
# ------------------------------------------------------------
debug: CFLAGS := $(BASE_CFLAGS) $(DEBUG_FLAGS)
debug: LDFLAGS :=
debug: prep $(TARGET)

# ------------------------------------------------------------
# Release Build
# ------------------------------------------------------------
release: CFLAGS := $(BASE_CFLAGS) $(RELEASE_FLAGS)
release: LDFLAGS :=
release: prep $(TARGET)

# ------------------------------------------------------------
# AddressSanitizer + UBSan Build
# ------------------------------------------------------------
sanitize: CFLAGS := $(BASE_CFLAGS) $(DEBUG_FLAGS) $(SANITIZER_FLAGS)
sanitize: LDFLAGS := $(SANITIZER_FLAGS)
sanitize: prep $(TARGET)

# ------------------------------------------------------------
# ThreadSanitizer Build
# ------------------------------------------------------------
tsan: CFLAGS := $(BASE_CFLAGS) $(DEBUG_FLAGS) $(THREAD_SANITIZER_FLAGS)
tsan: LDFLAGS := $(THREAD_SANITIZER_FLAGS)
tsan: prep $(TARGET)

# ------------------------------------------------------------
# Create Build Directories
# ------------------------------------------------------------
prep:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)

# ------------------------------------------------------------
# Linking
# ------------------------------------------------------------
$(TARGET): $(OBJS)
	@echo "[LINK] $@"
	$(CC) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

# ------------------------------------------------------------
# Compilation Rule
# ------------------------------------------------------------
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# ------------------------------------------------------------
# Include Dependency Files
# ------------------------------------------------------------
-include $(DEPS)

# ------------------------------------------------------------
# Valgrind
# ------------------------------------------------------------
valgrind: debug
	valgrind \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		./$(TARGET)

# ------------------------------------------------------------
# Quick Run Target
# ------------------------------------------------------------
run: debug
	./$(TARGET)

# ------------------------------------------------------------
# Clean
# ------------------------------------------------------------
clean:
	@echo "[CLEAN]"
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# ------------------------------------------------------------
# Full Rebuild
# ------------------------------------------------------------
rebuild: clean debug

# ------------------------------------------------------------
# Install
# ------------------------------------------------------------
install: release
	sudo cp $(TARGET) /usr/local/bin/opus

# ------------------------------------------------------------
# Uninstall
# ------------------------------------------------------------
uninstall:
	sudo rm -f /usr/local/bin/opus

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
help:
	@echo ""
	@echo "OPUS Build Targets"
	@echo "------------------------------------"
	@echo "make debug      - Debug build"
	@echo "make release    - Optimized release build"
	@echo "make sanitize   - ASan + UBSan build"
	@echo "make tsan       - ThreadSanitizer build"
	@echo "make valgrind   - Run Valgrind"
	@echo "make run        - Build and run"
	@echo "make clean      - Remove build artifacts"
	@echo "make rebuild    - Full rebuild"
	@echo "make install    - Install OPUS"
	@echo "make uninstall  - Remove installed binary"
	@echo ""

# ------------------------------------------------------------
# Phony Targets
# ------------------------------------------------------------
.PHONY: \
	all \
	debug \
	release \
	sanitize \
	tsan \
	valgrind \
	run \
	clean \
	rebuild \
	install \
	uninstall \
	help \
	prep \
