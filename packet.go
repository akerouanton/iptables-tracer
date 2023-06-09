package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketDecoder struct {
	// Cache the gopacket.LayerClass used internally to print packets' L4
	l4Class gopacket.LayerClass
}

func NewPacketDecoder() PacketDecoder {
	l4Class := make([]gopacket.LayerType, 0)
	l4Class = append(l4Class, layers.LayerClassIPTransport.LayerTypes()...)
	l4Class = append(l4Class, layers.LayerClassIPControl.LayerTypes()...)

	return PacketDecoder{
		l4Class: gopacket.NewLayerClass(l4Class),
	}
}

type packet struct {
	l3 string
	l4 string
}

func (pkt packet) Headers() string {
	return pkt.l3 + pkt.l4
}

func (d PacketDecoder) Decode(payload []byte, family IPFamily) (packet, error) {
	var firstLayer gopacket.Decoder
	if family == AfInet4 {
		firstLayer = layers.LayerTypeIPv4
	} else {
		firstLayer = layers.LayerTypeIPv6
	}

	gopkt := gopacket.NewPacket(payload, firstLayer, gopacket.DecodeOptions{
		NoCopy: true,
		Lazy:   true,
	})

	var pkt packet
	l3 := gopkt.NetworkLayer()
	switch l3.(type) {
	case *layers.IPv4:
		ipv4 := l3.(*layers.IPv4)
		pkt.l3 = fmt.Sprintf(
			"SRC=%s DST=%s LEN=%d TOS=%02x TTL=%d ID=%d PROTO=%s ",
			ipv4.SrcIP, ipv4.DstIP, ipv4.Length, ipv4.TOS, ipv4.TTL, ipv4.Id, ipv4.Protocol)
	case *layers.IPv6:
		ipv6 := l3.(*layers.IPv6)
		pkt.l3 = fmt.Sprintf(
			"SRC=%s DST=%s LEN=%d HOP=%d ",
			ipv6.SrcIP, ipv6.DstIP, ipv6.Length, ipv6.HopLimit)

		if ipv6.NextHeader == layers.IPProtocolTCP ||
			ipv6.NextHeader == layers.IPProtocolUDP ||
			ipv6.NextHeader == layers.IPProtocolICMPv6 {
			pkt.l3 += fmt.Sprintf("PROTO=%s ", ipv6.NextHeader)
		}
	default:
		return packet{}, fmt.Errorf("could not parse network layer: %+v", l3)
	}

	l4 := gopkt.LayerClass(d.l4Class)
	switch l4.(type) {
	case *layers.TCP:
		tcp := l4.(*layers.TCP)
		flags := tcpFlags(tcp)
		pkt.l4 = fmt.Sprintf(
			"SPT=%d DPT=%d FLAGS=%s SEQ=%d CSUM=%x ",
			tcp.SrcPort, tcp.DstPort, strings.Join(flags, ","), tcp.Seq, tcp.Checksum)
	case *layers.UDP:
		udp := l4.(*layers.UDP)
		pkt.l4 = fmt.Sprintf("SPT=%d DPT=%d CSUM=%x ",
			udp.SrcPort, udp.DstPort, udp.Checksum)
	case *layers.ICMPv4:
		icmp := l4.(*layers.ICMPv4)
		pkt.l4 = fmt.Sprintf("TYPE/CODE=%s CSUM=%x ",
			icmp.TypeCode, icmp.Checksum)
	case *layers.ICMPv6:
		icmp := l4.(*layers.ICMPv6)
		pkt.l4 = fmt.Sprintf("TYPE/CODE=%s CSUM=%x ",
			icmp.TypeCode, icmp.Checksum)
	default:
		return packet{}, fmt.Errorf("could not parse transport layer: %+v", l4)
	}

	return pkt, nil
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
