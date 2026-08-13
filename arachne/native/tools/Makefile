ARCH := $(shell uname -m)
BUILD_DIR := build
BIN := $(BUILD_DIR)/byte_inspector

.PHONY: all clean check-arch

all: check-arch $(BIN)

check-arch:
ifneq ($(ARCH),arm64)
	$(error Bu arac sadece Apple Silicon (arm64) Mac'lerde derlenir. Tespit edilen mimari: $(ARCH))
endif

$(BIN): byte_inspector.s
	@mkdir -p $(BUILD_DIR)
	clang -arch arm64 -o $(BIN) byte_inspector.s
	@echo "Derlendi: $(BIN)"
	@echo "Deneme: $(BIN) /etc/hosts"

clean:
	rm -rf $(BUILD_DIR)
