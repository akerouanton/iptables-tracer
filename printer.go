package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

type Printer struct {
	// Whether raw ipt rules should be printed when packets hit them
	printRaw bool
	// Whether physin/physout should be printed
	printPhys bool

	// Cache the gopacket.LayerClass used internally to print packets' L4
	l4Class gopacket.LayerClass
}

func NewPrinter(cfg Config) Printer {
	l4Class := make([]gopacket.LayerType, 0)
	l4Class = append(l4Class, layers.LayerClassIPTransport.LayerTypes()...)
	l4Class = append(l4Class, layers.LayerClassIPControl.LayerTypes()...)

	return Printer{
		printRaw:  cfg.PrintRaw,
		printPhys: cfg.PrintPhys,
		l4Class:   gopacket.NewLayerClass(l4Class),
	}
}

func (pr Printer) printIptRule(traceEvt traceEvent, family IPFamily) {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("\t%s %s ", traceEvt.tableName, traceEvt.chainName))

	// TODO: check if the NFMARK is really available through Mark
	if traceEvt.attrs.Mark != nil {
		b.WriteString(fmt.Sprintf("NFMARK=0x%x ", *traceEvt.attrs.Mark))
	} else {
		b.WriteString("NFMARK=0x0 ")
	}

	b.WriteString("\n")

	chain, err := GetIptChain(family, traceEvt.tableName, traceEvt.chainName)
	if err != nil {
		logrus.Errorf("Could not get iptables chain %s from table %s: %s",
			traceEvt.chainName, traceEvt.tableName, err)
	}

	if traceEvt.traceType == "policy" {
		b.WriteString("\t\tDEFAULT POLICY")
		b.WriteString(fmt.Sprintf("\n\t\t=> %s", color.HiGreenString(chain.Policy)))
	} else if traceEvt.traceType == "rule" {
		rule := chain.Rules[traceEvt.ruleNum-1]

		b.WriteString(fmt.Sprintf("\t\tMATCH RULE (#%d)", traceEvt.ruleNum))
		if pr.printRaw {
			b.WriteString(fmt.Sprintf(": %s", rule))
		}

		target, targetFlags := parseIptRuleTarget(rule)

		if target == "ACCEPT" {
			target = color.HiGreenString(target)
		} else if target == "DROP" {
			target = color.HiRedString(target)
		} else {
			target = color.HiBlueString(target)
		}
		b.WriteString(fmt.Sprintf("\n\t\t=> %s", target))

		if targetFlags != "" {
			b.WriteString(fmt.Sprintf(": %s", targetFlags))
		}
	} else if traceEvt.traceType == "return" {
		b.WriteString(fmt.Sprintf("\t\t=> %s", color.HiBlueString("RETURN")))
	}

	fmt.Println(b.String())
}

func (pr Printer) printPacketHeaders(traceEvt traceEvent, family IPFamily, ifaceCache *IfaceCache) {
	b := strings.Builder{}

	indev, _ := ifaceCache.IndexToName(traceEvt.attrs.InDev)
	outdev, _ := ifaceCache.IndexToName(traceEvt.attrs.OutDev)
	b.WriteString(fmt.Sprintf("IN=%s OUT=%s ", indev, outdev))

	if pr.printPhys {
		physindev, _ := ifaceCache.IndexToName(traceEvt.attrs.PhysInDev)
		physoutdev, _ := ifaceCache.IndexToName(traceEvt.attrs.PhysOutDev)
		b.WriteString(fmt.Sprintf("PHYSIN=%s PHYSOUT=%s ", physindev, physoutdev))
	}

	var firstLayer gopacket.Decoder
	if family == AfInet4 {
		firstLayer = layers.LayerTypeIPv4
	} else {
		firstLayer = layers.LayerTypeIPv6
	}

	packet := gopacket.NewPacket(*traceEvt.attrs.Payload, firstLayer, gopacket.DecodeOptions{
		NoCopy: true,
		Lazy:   true,
	})

	l3 := packet.NetworkLayer()
	switch l3.(type) {
	case *layers.IPv4:
		ipv4 := l3.(*layers.IPv4)
		b.WriteString(fmt.Sprintf(
			"SRC=%s DST=%s LEN=%d TOS=%02x TTL=%d ID=%d PROTO=%s ",
			ipv4.SrcIP, ipv4.DstIP, ipv4.Length, ipv4.TOS, ipv4.TTL, ipv4.Id, ipv4.Protocol))
	case *layers.IPv6:
		ipv6 := l3.(*layers.IPv6)
		b.WriteString(fmt.Sprintf(
			"SRC=%s DST=%s LEN=%d HOP=%d ",
			ipv6.SrcIP, ipv6.DstIP, ipv6.Length, ipv6.HopLimit))

		if ipv6.NextHeader == layers.IPProtocolTCP ||
			ipv6.NextHeader == layers.IPProtocolUDP ||
			ipv6.NextHeader == layers.IPProtocolICMPv6 {
			b.WriteString(fmt.Sprintf("PROTO=%s ", ipv6.NextHeader))
		}
	default:
		logrus.Warn("Could not parse network layer")
	}

	l4 := packet.LayerClass(pr.l4Class)
	switch l4.(type) {
	case *layers.TCP:
		tcp := l4.(*layers.TCP)
		flags := tcpFlags(tcp)
		b.WriteString(fmt.Sprintf(
			"SPT=%d DPT=%d FLAGS=%s SEQ=%d CSUM=%x ",
			tcp.SrcPort, tcp.DstPort, strings.Join(flags, ","), tcp.Seq, tcp.Checksum))
	case *layers.UDP:
		udp := l4.(*layers.UDP)
		b.WriteString(fmt.Sprintf("SPT=%d DPT=%d CSUM=%x ",
			udp.SrcPort, udp.DstPort, udp.Checksum))
	case *layers.ICMPv4:
		icmp := l4.(*layers.ICMPv4)
		b.WriteString(fmt.Sprintf("TYPE/CODE=%s CSUM=%x ",
			icmp.TypeCode, icmp.Checksum))
	case *layers.ICMPv6:
		icmp := l4.(*layers.ICMPv6)
		b.WriteString(fmt.Sprintf("TYPE/CODE=%s CSUM=%x ",
			icmp.TypeCode, icmp.Checksum))
	default:
		logrus.Warnf("Could not parse transport layer: %+v", l4)
	}

	fmt.Println(b.String())
}

func tcpFlags(tp *layers.TCP) []string {
	flags := make([]string, 0)

	if tp.SYN {
		flags = append(flags, "SYN")
	}
	if tp.RST {
		flags = append(flags, "RST")
	}
	if tp.FIN {
		flags = append(flags, "FIN")
	}
	if tp.PSH {
		flags = append(flags, "PSH")
	}
	if tp.ACK {
		flags = append(flags, "ACK")
	}
	if tp.URG {
		flags = append(flags, "URG")
	}

	return flags
}
