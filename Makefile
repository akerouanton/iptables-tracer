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
		--platform=linux/amd64 --include=/bin/iptables-tracer $(IMAGE) /undock
	mv bin/iptables-tracer bin/iptables-tracer-amd64

	docker run --rm -v $(shell pwd):/undock -w /undock crazymax/undock:latest \
		--platform=linux/arm64 --include=/bin/iptables-tracer $(IMAGE) /undock
	mv bin/iptables-tracer bin/iptables-tracer-arm64

install:
	sudo cp bin/iptables-tracer /usr/local/sbin/iptables-tracer
