.PHONY: all clean

TARGET_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),dns/target)
PROFILE := debug

all:
	cargo build --manifest-path dns/Cargo.toml
	cp $(TARGET_DIR)/$(PROFILE)/main .

clean:
	cargo clean --manifest-path dns/Cargo.toml
	rm -f main