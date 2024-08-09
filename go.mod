module github.com/akerouanton/iptables-tracer

go 1.22

require (
	github.com/fatih/color v1.15.0
	github.com/florianl/go-nflog/v2 v2.0.1
	github.com/google/gopacket v1.1.19
	github.com/mdlayher/netlink v1.4.1
	github.com/sirupsen/logrus v1.9.2
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
)

replace github.com/mdlayher/netlink v1.4.1 => github.com/mdlayher/netlink v1.7.2
