build:
	LIBPCAP_VER=1.10.1 LIBPCAP_LIBDIR=$(shell pwd)/lib cargo build --target=x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/debug/virtual_sensor ./sensor

release:
	LIBPCAP_VER=1.10.1 LIBPCAP_LIBDIR=$(shell pwd)/lib cargo build --release --target=x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/debug/virtual_sensor ./sensor
vendor:
	cargo vendor ThirdPartySourceOriginal

clean:
	rm -rf target 2>&1 >/dev/null

lint:
	cargo clippy --fix

run:
	sudo RUST_BACKTRACE=1 ./sensor Config.toml

redis:
	docker run -p 6379:6379 --name redis --detach --restart always redis:latest

git_clean_local:
	git fetch -p && git branch -vv | awk '/: gone]/{print $1}' | xargs git branch -D