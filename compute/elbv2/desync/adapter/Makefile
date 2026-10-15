# Requires a Rust/Cargo toolchain, cbindgen and a Linux C compiler/linker.
# make -C compute/elbv2/desync/adapter GUARDIAN=/absolute/path/to/pinned/clone install
GUARDIAN ?= $(abspath ../../../../clones/http-desync-guardian)
PREFIX ?= /usr/local
DESTDIR ?=
CC ?= cc
CBINDGEN ?= cbindgen
CFLAGS ?= -O2 -Wall -Wextra -Werror
PIN := f0b15a772926ca47cf6216c73df8cfeaae02cd75
BUILD := $(CURDIR)/build
SOURCE := $(BUILD)/source

.PHONY: all install clean
all:
	test "$$(git -C "$(GUARDIAN)" rev-parse HEAD)" = "$(PIN)"
	test -z "$$(git -C "$(GUARDIAN)" status --porcelain --untracked-files=no)"
	test "$$("$(CBINDGEN)" --version)" = "cbindgen 0.29.2"
	mkdir -p "$(BUILD)"
	rm -rf "$(SOURCE)"
	mkdir -p "$(SOURCE)"
	git -C "$(GUARDIAN)" archive "$(PIN)" | tar -x -C "$(SOURCE)"
	install -m 0644 Cargo.lock "$(SOURCE)/Cargo.lock"
	cargo build --manifest-path "$(SOURCE)/Cargo.toml" --locked --release --target-dir "$(BUILD)/guardian"
	"$(CBINDGEN)" "$(SOURCE)" --config "$(SOURCE)/cbindgen.toml" --output "$(BUILD)/http_desync_guardian.h" --lang c
	$(CC) $(CFLAGS) -I"$(BUILD)" main.c "$(BUILD)/guardian/release/libhttp_desync_guardian.a" -lpthread -ldl -lm -lrt -lutil -o "$(BUILD)/stackd-http-desync-guardian"

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 "$(BUILD)/stackd-http-desync-guardian" "$(DESTDIR)$(PREFIX)/bin/stackd-http-desync-guardian"

clean:
	rm -rf "$(BUILD)"
