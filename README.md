# iptables-tracer

This program will help you see packets going through your iptables rules. It supports:

* Both IPv4 & IPv6 ;
* Only supports iptables for now (neither iptables-nft nor nftables are supported) ;
* Has a `-filter` flag that supports cBPF filter syntax ;
* Can filter based on input/output interface (see `-iface` flag) ;
* Prints packets' L2, L3 and L4 headers, including ICMP and ICMPv6 ;
* Automatically inserts the kernel module `nfnetlink_log` ;

## Install

```shell
$ wget -O iptables-tracer https://github.com/akerouanton/iptables-tracer/releases/download/v0.1/iptables-tracer-amd64
$ sudo mv iptables-tracer /usr/local/sbin/iptables-tracer
$ sudo chmod +x /usr/local/sbin/iptables-tracer
```

## How to use

Standalone binary:

```console
$ sudo iptables-tracer -filter='tcp port 8080'
$ sudo iptables-tracer -family ipv6 filter='icmp6'
$ iptables-tracer -help
Usage of iptables-tracer:
  -family string
    	Either: ipv4 or ipv6 (default "ipv4")
  -filter string
    	A cBPF filter to select specific packets
  -filter-chain string
    	Print only ipt decisions for given table/chains. Use a comma to specify multiple chains.
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

If you want to use the Docker image `albinkerouanton006/iptables-tracer`, you'll need to manually set the following sysctls:

- `net.netfilter.nf_log.2=nfnetlink_log`
- `net.netfilter.nf_log.10=nfnetlink_log`

If you want to run that image to debug a DinD issue, you need to pass these sysctls to the dind container through `--sysctl=...`.

```console
# First, change the required sysctls:
$ docker exec <dind_cid> sysctl net.netfilter.nf_log.2=nfnetlink_log \
	net.netfilter.nf_log.10=nfnetlink_log

# Then, attach to a dind container:
$ docker run --rm -it --net=container:<dind_cid> --privileged albinkerouanton006/iptables-tracer -family ipv6 -filter 'tcp port 8000'
```

If you see that `iptables-tracer` doesn't start correctly (it's spinning forever), or if you see an error message about procfs not being writable, you should try to add `-skip-modprobe`. In that case, you'll need to make sure the above sysctls are properly set and eventually load the kernel module `nfnetlink_log` manually.

### One-liners

```console
# Trace only IPv6 Neighbor Solicitation & Neighbor Advertisment 
$ sudo iptables-tracer -family ipv6 -iface=br-21502e5b2c6c -filter='icmp6 and (ip6[40] == 135 || ip6[40] == 136)'

# Execute iptables-tracer into a specific container
$ sudo iptables-tracer -netns="$(docker inspect --format='{{ .NetworkSettings.SandboxKey }}' tender_merkle)" -family ipv6

# Trace connections to port 8080 going through iface eth0
$ sudo iptables-tracer -iface eth0 -filter 'port 8080'

# Trace ICMP packets
$ sudo iptables-tracer -filter icmp
```

### Example

```console
$ sudo iptables-tracer -netns="$(docker inspect --format='{{ .NetworkSettings.SandboxKey }}' tender_merkle)" -family ipv4 -filter="tcp port 1242"
INFO[0000] Tracer switched to netns /var/run/docker/netns/e859696c843d. Forking.. 
INFO[0000] Waiting for trace events...                  
IN=hairpin-8-2 OUT= SRC=172.22.0.2 DST=172.17.0.3 LEN=60 TOS=00 TTL=64 ID=3588 PROTO=TCP SPT=53920 DPT=1242 FLAGS=SYN SEQ=3083952015 CSUM=585b 
	raw PREROUTING NFMARK=0x0 
		DEFAULT POLICY
		=> ACCEPT
	nat PREROUTING NFMARK=0x0 
		MATCH RULE (#1): -m addrtype --dst-type LOCAL -j DOCKER
		=> DOCKER
	nat DOCKER NFMARK=0x0 
		MATCH RULE (#1): -p tcp -m tcp --dport 1242 -j DNAT --to-destination 172.23.0.2:1242
		=> DNAT: --to-destination 172.23.0.2:1242
	filter FORWARD NFMARK=0x0 IN=hairpin-8-2 OUT=hairpin-8-1 (changed by last rule)
		MATCH RULE (#1): -j DOCKER-USER
		=> DOCKER-USER
	filter DOCKER-USER NFMARK=0x0 
		=> RETURN
	filter FORWARD NFMARK=0x0 
		MATCH RULE (#2): -j DOCKER-ISOLATION-STAGE-1
		=> DOCKER-ISOLATION-STAGE-1
	filter DOCKER-ISOLATION-STAGE-1 NFMARK=0x0 
		MATCH RULE (#2): -i hairpin-8-2 ! -o hairpin-8-2 -j DOCKER-ISOLATION-STAGE-2
		=> DOCKER-ISOLATION-STAGE-2
	filter DOCKER-ISOLATION-STAGE-2 NFMARK=0x0 
		MATCH RULE (#1): -o hairpin-8-1 -j DROP
		=> DROP
```
