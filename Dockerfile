FROM golang:1.20-bookworm AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends bison flex && \
    rm -r /var/lib/apt/*

WORKDIR /build

ENV LIBPCAP_VERSION=1.10.4
RUN wget http://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz && \
    tar xvf libpcap-${LIBPCAP_VERSION}.tar.gz && \
    cd libpcap-${LIBPCAP_VERSION} && \
    ./configure && \
    make

COPY . /build

ENV LD_LIBRARY_PATH="-L/build/libpcap-${LIBPCAP_VERSION}" \
    CGO_LDFLAGS="-L/build/libpcap-${LIBPCAP_VERSION}" \
    CGO_CPPFLAGS="-I/build/libpcap-${LIBPCAP_VERSION}"
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-linkmode 'external' -extldflags '-static' -s -w" -o bin/iptables-tracer .

####################

FROM scratch AS binary
WORKDIR /bin
COPY --from=build /build/bin/iptables-tracer /bin/
