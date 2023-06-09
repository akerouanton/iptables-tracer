.PHONY: build
build:
	if [ ! -d bin/ ]; then mkdir bin; fi
	go build -o bin/iptables-tracer ./

install:
	sudo cp bin/iptables-tracer /usr/local/sbin/iptables-tracer
