IMAGE_TAG = albinkerouanton006/iptables-tracer:latest
BUILD_OPTS =

ifdef BUILDER
BUILD_OPTS := --builder=${BUILDER}
endif

.PHONY: binary
binary:
	if [ ! -d bin/ ]; then mkdir bin; fi
	docker build --push --platform linux/amd64,linux/arm64 ${BUILD_OPTS} -t ${IMAGE_TAG} --target=binary .
	undock --include=/bin docker-daemon://${IMAGE_TAG} .

install:
	sudo cp bin/iptables-tracer /usr/local/sbin/iptables-tracer
