package vrrp

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
)

const (
	nat           = "nat"
	vrrp          = "VRRP-GO"
	prerouting    = "PREROUTING"
	dnat          = "DNAT"
	jump          = "-j"
	destination   = "-d"
	toDestination = "--to-destination"
)

func newForwarder() (*forwarder, error) {
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("'sysctl -w net.ipv4.ip_forward=1' failed: %v %v", string(out), err)
	}
	iptables, err := iptables.New()
	if err != nil {
		return nil, err
	}
	fw := &forwarder{iptables: iptables}
	if err := fw.init(); err != nil {
		return nil, err
	}
	return fw, nil
}

type forwarder struct {
	iptables *iptables.IPTables
}

func (f *forwarder) init() error {
	ok, err := f.iptables.ChainExists(nat, vrrp)
	if err != nil {
		return err
	}
	if !ok {
		if err := f.iptables.NewChain(nat, vrrp); err != nil {
			return err
		}
	}
	if err := f.iptables.AppendUnique(nat, prerouting, jump, vrrp); err != nil {
		return err
	}
	return nil
}

func (f *forwarder) start(vr *VirtualRouter) error {
	for k := range vr.protectedIPAddrs {
		ip := net.IP(k[:]).To4()
		if err := f.iptables.AppendUnique(nat, vrrp, destination, ip.String(), jump, dnat, toDestination, vr.preferredSourceIP.String()); err != nil {
			return err
		}
	}
	return nil
}

func (f *forwarder) stop() error {
	return f.iptables.ClearChain(nat, vrrp)
}

func (f *forwarder) close() error {
	if err := f.iptables.Delete(nat, prerouting, jump, vrrp); err != nil {
		return err
	}
	return f.iptables.ClearAndDeleteChain(nat, vrrp)
}
