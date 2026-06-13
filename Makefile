default: all

.PHONY: fmt build test commit fix doc all

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

all: fmt build test commit fix test doc
