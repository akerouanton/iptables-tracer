IMAGE_TAG ?= latest
IMAGE = albinkerouanton006/iptables-tracer:$(IMAGE_TAG)
BUILD_OPTS =

ifdef BUILDER
BUILD_OPTS := --builder=${BUILDER}
endif

.PHONY: build
build:
	docker build --platform linux/amd64,linux/arm64 --load ${BUILD_OPTS} -t ${IMAGE} --target=final .

.PHONY: push
push:
	docker push $(IMAGE)

.PHONY: binary
binary: build
	if [ ! -d bin/ ]; then mkdir bin; fi
	docker run --rm -v $(shell pwd):/undock -w /undock crazymax/undock:latest \
		--include=/bin/iptables-tracer $(IMAGE) /undock

install:
	sudo cp bin/iptables-tracer /usr/local/sbin/iptables-tracer
