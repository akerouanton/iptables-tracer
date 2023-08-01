package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/netlink"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

type IPFamily string

const (
	AfInet4 = IPFamily("ipv4")
	AfInet6 = IPFamily("ipv6")
)

type Filter struct {
	Bytecode string
	Raw      string
}

func NewFilter(rawFilter string) (Filter, error) {
	instrs, err := pcap.CompileBPFFilter(12, -1, rawFilter)
	if err != nil {
		return Filter{}, fmt.Errorf("invalid filter %q: %w", rawFilter, err)
	}

	if len(instrs) > 64 {
		return Filter{}, fmt.Errorf("compiled BPF filter can't be larger than 64 instructions")
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("%d", len(instrs)))
	for _, instr := range instrs {
		b.WriteString(fmt.Sprintf(",%d %d %d %d", instr.Code, instr.Jt, instr.Jf, instr.K))
	}

	return Filter{
		Bytecode: b.String(),
		Raw:      rawFilter,
	}, nil
}

func parseFlags() Config {
	if flagLogLvl != "" {
		if logLvl, err := logrus.ParseLevel(flagLogLvl); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		} else {
			logrus.SetLevel(logLvl)
		}
	}

	if flagFamily != string(AfInet4) && flagFamily != string(AfInet6) {
		fmt.Fprintf(os.Stderr, "ERROR: -family should be either ipv4 or ipv6. Got: %s\n", flagFamily)
		os.Exit(1)
	}

	var filter Filter
	if flagFilter != "" {
		var err error
		if filter, err = NewFilter(flagFilter); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
			os.Exit(1)
		}
	}

	var netnsPath string
	if flagNetns != "" {
		if _, err := os.Stat(flagNetns); err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "ERROR: %s doesn't exist\n", flagNetns)
			} else {
				fmt.Fprintf(os.Stderr, "ERROR: could not stat netns handle %s: %s\n", flagNetns, err)
			}
			os.Exit(1)
		} else {
			netnsPath = flagNetns
		}
	}

	ifaces := []string{""}
	if flagIface != "" {
		ifaces = strings.Split(flagIface, ",")
	}

	chains := make([][]string, 0)
	if flagFilterChain != "" {
		for _, part := range strings.Split(flagFilterChain, ",") {
			subparts := strings.Split(part, "/")
			if len(subparts) != 2 {
				fmt.Fprintf(os.Stderr, "ERROR: chain filter %q is badly formated. Format: <table>/<chain>.", part)
				os.Exit(1)
			}
			chains = append(chains, subparts)
		}
	}

	return Config{
		IPFamily:          IPFamily(flagFamily),
		Filter:            filter,
		FilterIfaces:      ifaces,
		FilterChains:      chains,
		NetnsPath:         netnsPath,
		FlushRaw:          flagFlushRaw,
		PrintRaw:          flagPrintRaw,
		PrintPhys:         flagPrintPhys,
		PrintIfaceChanges: flagPrintIfaceChanges,
	}
}

var (
	flagFamily            string
	flagFilter            string
	flagIface             string
	flagFilterChain       string
	flagFlushRaw          bool
	flagNetns             string
	flagPrintRaw          bool
	flagPrintPhys         bool
	flagPrintIfaceChanges bool
	flagLogLvl            string
)

type Config struct {
	IPFamily     IPFamily
	Filter       Filter
	FilterIfaces []string
	FilterChains [][]string
	NetnsPath    string
	// Whether raw table should be flushed before adding our own rules
	FlushRaw bool
	// Whether raw ipt rules should be printed when packets hit them
	PrintRaw bool
	// Whether physin/physout should be printed
	PrintPhys bool
	// Whether interface changes should be printed. WARNING: memory will grow unbounded.
	PrintIfaceChanges bool
}

func insNfNetlinkLog() {
	cmd := exec.Command("modprobe", "nfnetlink_log")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			logrus.Fatalf("Could not modprobe nfnetlink_log (exit code: %d): %s", e.ExitCode(), string(out))
		} else {
			logrus.Fatalf("Could not modprobe nfnetlink_log: %v", err)
		}
	}
}

func reexecSelf() {
	args := os.Args[1:]
	for i, arg := range args {
		if strings.HasPrefix(arg, "-netns=") || strings.HasPrefix(arg, "--netns") {
			args = append(args[:i], args[i+1:]...)
			break
		} else if arg == "-netns" || arg == "--netns" {
			args = append(args[:i], args[i+2:]...)
		}
	}

	reexecCmd := exec.Command("/proc/self/exe", args...)
	reexecCmd.Stdin = os.Stdin
	reexecCmd.Stdout = os.Stdout
	reexecCmd.Stderr = os.Stderr

	err := reexecCmd.Run()
	if err == nil {
		os.Exit(0)
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}
	logrus.Fatal(err)
}

func main() {
	// TODO: add a way to filter in/out specific ipt tables/chains
	// TODO: support tracing both AF at the same time
	flag.StringVar(&flagFamily, "family", string(AfInet4), "Either: ipv4 or ipv6")
	flag.StringVar(&flagFilter, "filter", "", "A cBPF filter to select specific packets")
	flag.StringVar(&flagIface, "iface", "", "Only trace packets coming from/to specific interface(s). Use a comma to specify multiple interfaces.")
	flag.StringVar(&flagFilterChain, "filter-chain", "", "Print only ipt decisions for given table/chains. Use a comma to specify multiple chains.")
	flag.BoolVar(&flagFlushRaw, "flush", true, "Whether the RAW chains should be flushed before adding tracing rules.")
	flag.StringVar(&flagNetns, "netns", "", "Path to a netns handle where the tracer should be executed")
	flag.BoolVar(&flagPrintRaw, "print-raw", true, "Whether raw iptables rules should be printed when packets hit them")
	flag.BoolVar(&flagPrintPhys, "print-phys", false, "Whether physin/physout should be printed")
	flag.BoolVar(&flagPrintIfaceChanges, "print-iface-changes", true, "Whether iface changes should be printed. WARNING: memory will grow unbounded.")
	flag.StringVar(&flagLogLvl, "log-level", "info", "Log level (panic, fatal, error, warn, info, debug or trace)")
	flag.Parse()

	cfg := parseFlags()

	insNfNetlinkLog()

	if cfg.NetnsPath != "" {
		handle, err := netns.GetFromPath(cfg.NetnsPath)
		if err != nil {
			logrus.Fatalf("Could not get netns handle from path %s: %s", cfg.NetnsPath, err)
		}

		runtime.LockOSThread()
		if err := netns.Set(handle); err != nil {
			logrus.Fatalf("Could not switch to netns %s: %s", cfg.NetnsPath, err)
		}
		logrus.Infof("Tracer switched to netns %s. Forking..", cfg.NetnsPath)
		reexecSelf()
	}

	// github.com/florianl/go-nflog doesn't set the right value in  /proc/sys/net/netfilter/nf_log/*
	// If we don't set it, no packets will be transmitted to nfnetlink_log, making the tracer useless.
	if cfg.IPFamily == AfInet4 {
		if err := os.WriteFile("/proc/sys/net/netfilter/nf_log/2", []byte("nfnetlink_log"), 0644); err != nil {
			logrus.Errorf("Could not set nfnetlink_log in /proc/sys/net/netfilter/nf_log/2: %v", err)
			os.Exit(1)
		}
	} else {
		if err := os.WriteFile("/proc/sys/net/netfilter/nf_log/10", []byte("nfnetlink_log"), 0644); err != nil {
			logrus.Errorf("Could not set nfnetlink_log in /proc/sys/net/netfilter/nf_log/10: %v", err)
			os.Exit(1)
		}
	}

	reverters, err := setupIptRules(cfg.IPFamily, cfg.FlushRaw, cfg.FilterIfaces, cfg.Filter)
	if err != nil {
		logrus.Error(err)

		applyReverters(reverters)
		os.Exit(1)
	}

	ifaceCache := &IfaceCache{}
	ctxWatchIface, cancelWatchIface := context.WithCancel(context.Background())
	go func() {
		if err := ifaceCache.Watch(ctxWatchIface); err != nil {
			logrus.Error(err)
			applyReverters(reverters)
			os.Exit(1)
		}
	}()

	nf, err := nflog.Open(&nflog.Config{
		// From https://workshop.netfilter.org/2016/wiki/images/3/33/Nft-logging.pdf:
		// "nfnetlink_log always uses group 0"
		Group:    0,
		Copymode: nflog.CopyPacket,
		Bufsize:  65536,
	})
	if err != nil {
		logrus.Error(err)

		applyReverters(reverters)
		os.Exit(1)
	}
	defer nf.Close()

	d := NewPacketDecoder()

	pr := NewPrinter(cfg, ifaceCache)
	printer := func(attrs nflog.Attribute) int {
		logrus.Tracef("Received a new packet: % 02x\n", *attrs.Payload)
		logrus.Tracef("    attrs.Prefix: %s\n", *attrs.Prefix)

		traceEvt, err := newTraceEvent(d, attrs, cfg.IPFamily)
		if err != nil {
			logrus.Debugf("Invalid nfla: %v", err)
			return 0
		}

		// Every packet first reach the raw table, so we can dump its headers here first
		// and then no need to reprint it on subsequent trace events (that would make the output
		// noisy).
		if traceEvt.tableName == "raw" {
			pr.printPacketHeaders(traceEvt)
		}

		if len(cfg.FilterChains) == 0 {
			pr.printIptRule(traceEvt, cfg.IPFamily)
		} else {
			for _, filter := range cfg.FilterChains {
				if traceEvt.tableName == filter[0] && traceEvt.chainName == filter[1] {
					pr.printIptRule(traceEvt, cfg.IPFamily)
				}
			}
		}

		return 0
	}
	onErr := func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}

		logrus.Errorf("Could not receive nflog messages: %v", err)
		applyReverters(reverters)
		// TODO: revert /proc/sys/net/netfilter/nf_log/* + drain the multicast group to make sure next run won't get
		// stale traces.
		os.Exit(1)

		return 1 // Unreachable -- just to make Go compiler happy
	}

	ctxNflog, cancelNflog := context.WithCancel(context.Background())
	if err := nf.RegisterWithErrorFunc(ctxNflog, printer, onErr); err != nil {
		logrus.Errorf("Could not register nflog handler: %v", err)
		applyReverters(reverters)
		os.Exit(1)
	}

	logrus.Info("Waiting for trace events...")

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	// Let the tracer do its job until we receive a SIGINT.
	<-signalCh

	cancelWatchIface()
	cancelNflog()
	applyReverters(reverters)
}

type traceEvent struct {
	attrs      nflog.Attribute
	pkt        packet
	inDev      uint32
	outDev     uint32
	physInDev  uint32
	physOutDev uint32
	nfMark     uint32
	tableName  string
	chainName  string
	// traceType is either policy, rule or return
	traceType string
	ruleNum   int
}

func (traceEvt traceEvent) ifaces() [2]uint32 {
	return [2]uint32{traceEvt.inDev, traceEvt.outDev}
}

func newTraceEvent(d PacketDecoder, attrs nflog.Attribute, family IPFamily) (traceEvent, error) {
	if attrs.Prefix == nil || !strings.HasPrefix(*attrs.Prefix, "TRACE: ") {
		return traceEvent{}, errors.New("not a trace event")
	}
	if attrs.Payload == nil {
		return traceEvent{}, errors.New("nfla has no payload")
	}

	prefix := strings.Trim(*attrs.Prefix, " ")
	splitPrefix := strings.Split(prefix[7:], ":")

	if len(splitPrefix) != 4 {
		return traceEvent{}, fmt.Errorf("invalid prefix format: %s", prefix)
	}

	traceType := splitPrefix[2]
	if traceType != "policy" && traceType != "rule" && traceType != "return" {
		return traceEvent{}, fmt.Errorf("invalid trace type: %q (prefix: %s)", traceType, prefix)
	}

	pkt, err := d.Decode(*attrs.Payload, family)
	if err != nil {
		return traceEvent{}, nil
	}

	return traceEvent{
		pkt:        pkt,
		inDev:      derefUint32Or(attrs.InDev, 0),
		outDev:     derefUint32Or(attrs.OutDev, 0),
		physInDev:  derefUint32Or(attrs.PhysInDev, 0),
		physOutDev: derefUint32Or(attrs.PhysOutDev, 0),
		nfMark:     derefUint32Or(attrs.Mark, 0),
		tableName:  splitPrefix[0],
		chainName:  splitPrefix[1],
		traceType:  splitPrefix[2],
		ruleNum:    mustAtoi(splitPrefix[3]),
	}, nil
}

func derefUint32Or(p *uint32, d uint32) uint32 {
	if p == nil {
		return d
	}
	return *p
}

func mustAtoi(s string) int {
	r, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("Could not convert \"%s\" to an integer: %s", s, err))
	}
	return r
}
