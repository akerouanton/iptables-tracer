package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

type Direction int

const (
	Input Direction = iota
	Output
)

type RuleReverter func() error

func applyReverters(reverters []RuleReverter) {
	for _, reverter := range reverters {
		if err := reverter(); err != nil {
			logrus.Warnf("Rule reverter failed: %s", err)
		}
	}
}

func setupIptRules(family IPFamily, flushRaw bool, ifaces []string, filter Filter) ([]RuleReverter, error) {
	reverters := make([]RuleReverter, 0, 2*len(ifaces))

	if flushRaw {
		logrus.Debugf("Flushing RAW/PREROUTING and RAW/OUTPUT chains")

		if err := execIpt(family, []string{"-t", "raw", "-F", "PREROUTING"}); err != nil {
			return reverters, err
		}
		if err := execIpt(family, []string{"-t", "raw", "-F", "OUTPUT"}); err != nil {
			return reverters, err
		}
	}

	for _, iface := range ifaces {
		for _, dir := range []Direction{Input, Output} {
			reverter, err := addIptRule(family, dir, iface, filter)
			if err != nil {
				return reverters, err
			}
			reverters = append(reverters, reverter)
		}
	}

	return reverters, nil
}

func addIptRule(family IPFamily, dir Direction, iface string, filter Filter) (RuleReverter, error) {
	var iptChain string
	var ifaceFlag string

	if dir == Input {
		iptChain = "PREROUTING"
		ifaceFlag = "-i"
	} else {
		iptChain = "OUTPUT"
		ifaceFlag = "-o"
	}

	iptArgs := []string{"-t", "raw", "-A", iptChain}

	if len(iface) > 0 {
		iptArgs = append(iptArgs, ifaceFlag, iface)
	}

	// TODO: use a fwmark to make it possible to run multiple tracers concurrently
	if len(filter.Bytecode) > 0 {
		iptArgs = append(
			iptArgs,
			"-m", "bpf", "--bytecode", filter.Bytecode,
			"-m", "comment", "--comment", fmt.Sprintf("bpf: \"%s\"", filter.Raw))
	}

	iptArgs = append(iptArgs, "-j", "TRACE")

	if err := execIpt(family, iptArgs); err != nil {
		return func() error { return nil }, err
	}

	return func() error {
		iptArgs[2] = "-D"
		return execIpt(family, iptArgs)
	}, nil
}

func execIpt(family IPFamily, args []string) error {
	bin := "iptables"
	if family == AfInet6 {
		bin = "ip6tables"
	}

	logrus.Debugf("Executing: %s %s", bin, strings.Join(args, " "))

	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%s: %s", err, stderr.String())
		}
		return err
	}

	return nil
}

func execIptSave(family IPFamily, table string) (io.Reader, error) {
	bin := "iptables-save"
	if family == AfInet6 {
		bin = "ip6tables-save"
	}

	logrus.Debugf("Executing: %s -t %s", bin, table)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(bin, "-t", table)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s: %s", err, stderr.String())
		}
	}

	return &stdout, nil
}

type IptTable map[string]IptChain

type IptChain struct {
	Policy string
	Rules  []string
}

func parseIptSave(r io.Reader) (IptTable, error) {
	table := make(IptTable, 0)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			return IptTable{}, errors.New("unexpected new line found in iptables-save output")
		}

		// Parse chain header -- :INPUT ACCEPT [658229:723231403]
		if line[0] == ':' {
			parts := strings.SplitN(line[1:], " ", 3)
			chainName := parts[0]
			policy := parts[1]

			if policy == "-" {
				policy = "RETURN"
			}

			table[chainName] = IptChain{
				Policy: policy,
				Rules:  make([]string, 0),
			}
		}

		// Parse rule -- -A LIBVIRT_FWO -i virbr1 -j REJECT --reject-with icmp6-port-unreachable
		if line[0] == '-' {
			parts := strings.SplitN(line, " ", 3)

			chain := table[parts[1]]
			chain.Rules = append(chain.Rules, parts[2])
			table[parts[1]] = chain
		}
	}

	if err := scanner.Err(); err != nil {
		return IptTable{}, err
	}

	return table, nil
}

func GetIptChain(family IPFamily, tableName, chainName string) (IptChain, error) {
	saveOutput, err := execIptSave(family, tableName)
	if err != nil {
		return IptChain{}, err
	}

	table, err := parseIptSave(saveOutput)
	if err != nil {
		return IptChain{}, err
	}

	chain, ok := table[chainName]
	if !ok {
		return IptChain{}, fmt.Errorf("chain %s not found in table %s", chainName, tableName)
	}

	return chain, nil
}

func parseIptRuleTarget(raw string) (string, string) {
	i := strings.LastIndex(raw, "-j ")
	if i == -1 {
		logrus.Warnf("Could not find jump flag -j in: %s", raw)
		return "", ""
	}

	parts := strings.SplitN(raw[i+1:], " ", 3)

	var jumpFlags string
	if len(parts) == 3 {
		jumpFlags = parts[2]
	}
	return parts[1], jumpFlags
}
