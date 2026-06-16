default: all

.PHONY: fmt build test commit fix doc all example

example:
	for f in examples/*.rs; do \
		cargo run --example $$(basename $$f .rs); \
	done

fmt:
	cargo fmt

build:
	cargo build

test:
	cargo test

commit:
	git add .
	git commit --allow-empty-message -am ""

fix:
	cargo clippy --fix --allow-dirty

doc:
	cargo doc

all: fmt build test example commit fix test doc
