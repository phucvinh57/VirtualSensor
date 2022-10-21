build:
	LIBPCAP_VER=1.10.1 LIBPCAP_LIBDIR=$(shell pwd)/lib cargo build --target=x86_64-unknown-linux-musl

release:
	LIBPCAP_VER=1.10.1 LIBPCAP_LIBDIR=$(shell pwd)/lib cargo build --release --target=x86_64-unknown-linux-musl

vendor:
	cargo vendor ThirdPartySourceOriginal

clean:
	rm -rf target 2>&1 >/dev/null
lint:
	cargo clippy --fix
run:
	cargo run exampleConfig.toml
