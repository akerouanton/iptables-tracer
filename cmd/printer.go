package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

type Printer struct {
	// Whether raw ipt rules should be printed when packets hit them
	printRaw bool
	// Whether physin/physout should be printed
	printPhys bool
	// Whether ifaces should be tracked and changes printed
	printIfaceChanges bool

	ifaceCache   *IfaceCache
	ifaceTracker map[packet][2]uint32
}

func NewPrinter(cfg Config, ifaceCache *IfaceCache) Printer {
	return Printer{
		printRaw:          cfg.PrintRaw,
		printPhys:         cfg.PrintPhys,
		printIfaceChanges: cfg.PrintIfaceChanges,
		ifaceCache:        ifaceCache,
		ifaceTracker:      map[packet][2]uint32{},
	}
}

func (pr Printer) printIptRule(traceEvt traceEvent, family IPFamily) {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("\t%s %s ", traceEvt.tableName, traceEvt.chainName))

	// TODO: check if the NFMARK is really available through Mark
	if traceEvt.attrs.Mark != nil {
		b.WriteString(fmt.Sprintf("NFMARK=0x%x ", traceEvt.nfMark))
	} else {
		b.WriteString("NFMARK=0x0 ")
	}

	// TODO: improve this // IN and OUT are always displayed when one changes
	ifaces := traceEvt.ifaces()
	trackedIfaces := pr.ifaceTracker[traceEvt.pkt]
	if pr.printIfaceChanges {
		var changed bool
		if trackedIfaces[0] != ifaces[0] {
			indev, _ := pr.ifaceCache.IndexToName(traceEvt.inDev)
			b.WriteString(fmt.Sprintf("IN=%s ", indev))
			changed = true
		}
		if trackedIfaces[1] != ifaces[1] {
			outdev, _ := pr.ifaceCache.IndexToName(traceEvt.outDev)
			b.WriteString(fmt.Sprintf("OUT=%s ", outdev))
			changed = true
		}
		if changed {
			pr.ifaceTracker[traceEvt.pkt] = ifaces
			b.WriteString("(changed by last rule)")
		}
	}

	b.WriteString("\n")

	chain, err := GetIptChain(family, traceEvt.tableName, traceEvt.chainName)
	if err != nil {
		logrus.Errorf("Could not get iptables chain %s from table %s: %s", traceEvt.chainName, traceEvt.tableName, err)
	}

	if traceEvt.traceType == "policy" {
		b.WriteString("\t\tDEFAULT POLICY")
		b.WriteString(fmt.Sprintf("\n\t\t=> %s", color.HiGreenString(chain.Policy)))
	} else if traceEvt.traceType == "rule" {
		b.WriteString(fmt.Sprintf("\t\tMATCH RULE (#%d)", traceEvt.ruleNum))

		if len(chain.Rules) < traceEvt.ruleNum {
			b.WriteString(": (rule not found)")
			goto print
		}

		rule := chain.Rules[traceEvt.ruleNum-1]

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

print:
	fmt.Println(b.String())
}

func (pr Printer) printPacketHeaders(traceEvt traceEvent) {
	b := strings.Builder{}

	if pr.printIfaceChanges {
		pr.ifaceTracker[traceEvt.pkt] = traceEvt.ifaces()
	}

	indev, _ := pr.ifaceCache.IndexToName(traceEvt.inDev)
	outdev, _ := pr.ifaceCache.IndexToName(traceEvt.outDev)
	b.WriteString(fmt.Sprintf("IN=%s OUT=%s ", indev, outdev))

	if pr.printPhys {
		physindev, _ := pr.ifaceCache.IndexToName(traceEvt.physInDev)
		physoutdev, _ := pr.ifaceCache.IndexToName(traceEvt.physOutDev)
		b.WriteString(fmt.Sprintf("PHYSIN=%s PHYSOUT=%s ", physindev, physoutdev))
	}

	b.WriteString(traceEvt.pkt.Headers())
	fmt.Println(b.String())
}
