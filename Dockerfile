FROM golang:1.22.7-bookworm AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends bison flex && \
    rm -r /var/lib/apt/*

WORKDIR /build

ENV LIBPCAP_VERSION=1.10.5
RUN wget http://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz && \
    tar xvf libpcap-${LIBPCAP_VERSION}.tar.gz && \
    cd libpcap-${LIBPCAP_VERSION} && \
    ./configure && \
    make

COPY cmd/* /build

ENV LD_LIBRARY_PATH="-L/build/libpcap-${LIBPCAP_VERSION}" \
    CGO_LDFLAGS="-L/build/libpcap-${LIBPCAP_VERSION}" \
    CGO_CPPFLAGS="-I/build/libpcap-${LIBPCAP_VERSION}"
ARG TARGETOS TARGETARCH
RUN --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-linkmode 'external' -extldflags '-static' -s -w" -o bin/iptables-tracer .

####################

FROM alpine AS final
WORKDIR /bin
COPY --from=build /build/bin/iptables-tracer /bin/

RUN <<EOF
# iptables provides libxt_bpf.so, and iptables-legacy provides the legacy iptables
# binary.
apk add --no-cache iptables iptables-legacy

# Then delete iptables symlink (it points to iptables-nft), and replace it with
# a link to the legacy version.
rm /sbin/iptables /sbin/ip6tables
ln -s /sbin/iptables-legacy /sbin/iptables
ln -s /sbin/ip6tables-legacy /sbin/ip6tables

rm /sbin/iptables-save /sbin/ip6tables-save
ln -s /sbin/iptables-legacy-save /sbin/iptables-save
ln -s /sbin/ip6tables-legacy-save /sbin/ip6tables-save
EOF

COPY modprobe.sh /usr/sbin/modprobe

ENTRYPOINT ["iptables-tracer"]
