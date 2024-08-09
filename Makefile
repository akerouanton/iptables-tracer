IMAGE_TAG = albinkerouanton006/iptables-tracer:latest
BUILD_OPTS =

ifdef BUILDER
BUILD_OPTS := --builder=${BUILDER}
endif

.PHONY: build
build:
	docker build --platform linux/amd64,linux/arm64 --load ${BUILD_OPTS} -t ${IMAGE_TAG} --target=final .

.PHONY: push
push:
	docker push $(IMAGE_TAG)

.PHONY: binary
binary: build-push
	if [ ! -d bin/ ]; then mkdir bin; fi
	undock --include=/bin docker-daemon://${IMAGE_TAG} .

install:
	sudo cp bin/iptables-tracer /usr/local/sbin/iptables-tracer
