# iptables-tracer

This program will help you see packets going through your iptables rules. It supports:

* Both IPv4 & IPv6 ;
* Only support iptables for now (neither iptables-nft nor nftables are supported) ;
* Has a `-filter` flag that supports cBPF filter syntax ;
* Can filter based on input/output interface (see `-iface` flag) ;

## Install

Prerequisites:

* Arch Linux: `libpcap` / Ubuntu: `libpcap0.8`

Build: `make`. The binary file will be located in bin/.

## How to use

Example:

```console
# iptables-tracer -filter='tcp port 8080'
# iptables-tracer -family ipv6 filter='icmp6'
# iptables-tracer -help
Usage of iptables-tracer:
  -family string
    	Either: ipv4 or ipv6 (default "ipv4")
  -filter string
    	A cBPF filter to select specific packets
  -flush
    	Whether the RAW chains should be flushed before adding tracing rules. (default true)
  -iface string
    	Only trace packets coming from/to specific interface(s). Use a comma to specify multiple interfaces.
  -log-level string
    	Log level (panic, fatal, error, warn, info, debug or trace) (default "info")
  -netns string
    	Path to a netns handle where the tracer should be executed
  -print-phys
    	Whether physin/physout should be printed
  -print-raw
    	Whether raw iptables rules should be printed when packets hit them (default true)
```