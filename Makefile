.PHONY: build
build:
	if [ ! -d bin/ ]; then mkdir bin; fi
	go build -o bin/iptables-tracer ./
