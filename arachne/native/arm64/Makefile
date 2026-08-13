ARCH := $(shell uname -m)
BUILD_DIR := build
DYLIB := $(BUILD_DIR)/libaz_fast_scan.dylib

.PHONY: all test clean check-arch

all: check-arch $(DYLIB)

check-arch:
ifneq ($(ARCH),arm64)
	$(error Bu modul sadece Apple Silicon (arm64) Mac'lerde derlenir. Tespit edilen mimari: $(ARCH))
endif

$(DYLIB): fast_scan.s
	@mkdir -p $(BUILD_DIR)
	clang -arch arm64 -shared -o $(DYLIB) fast_scan.s
	@echo "Derlendi: $(DYLIB)"

test: all
	python3 -c "from arachne.native import signature_engine as s; \
print('native aktif mi:', s.NATIVE_ENGINE_ACTIVE); \
print('az_find test:', s.find('hello world', 'world')); \
print('contains_any test:', s.contains_any(\"1' union select\", ['union select', '<script>']))"

clean:
	rm -rf $(BUILD_DIR)
