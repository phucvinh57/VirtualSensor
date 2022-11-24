build:
	LIBPCAP_VER=1.9.1-3 LIBPCAP_LIBDIR=$(shell pwd)/lib cargo build
	cp target/debug/virtual_sensor ./sensor

release:
	cargo build --release
	cp target/debug/virtual_sensor ./sensor

lint:
	cargo clippy --fix

git_clean_local:
	git branch --merged >/tmp/merged-branches && nano /tmp/merged-branches && xargs git branch -d </tmp/merged-branches