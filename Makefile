.PHONY: all build test check fmt clippy fixtures clean

all: test check

build:
	cargo build --release

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

check:
	cargo run -q -- check examples/position/model.dg
	cargo run -q -- check examples/timing/model.dg
	cargo run -q -- check examples/rng/model.dg
	cargo run -q -- check examples/loot/model.dg
	cargo run -q -- check examples/stats/model.dg
	cargo run -q -- check examples/coverage/model.dg
	cargo run -q -- check examples/conflicts/model.dg
	cargo run -q -- check examples/refute/model.dg
	cargo run -q -- port examples/port/model.dg --to b2 > /dev/null

fixtures:
	python3 tools/make_fixtures.py

clean:
	cargo clean
