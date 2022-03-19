package vrrp

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type Option func(r *VirtualRouter) error

func WithVRID(id byte) Option {
	return func(r *VirtualRouter) error {
		r.id = id
		return nil
	}
}

func WithInterface(iface string) Option {
	return func(r *VirtualRouter) error {
		r.iface = iface
		return nil
	}
}

func WithIPvX(ipvx byte) Option {
	return func(r *VirtualRouter) error {
		if ipvx != IPv4 && ipvx != IPv6 {
			return fmt.Errorf("invalid ipvx: %v, must be IPv4 or IPv6", ipvx)
		}
		r.ipvX = ipvx
		return nil
	}
}

func WithOwner(owner bool) Option {
	return func(r *VirtualRouter) error {
		r.owner = owner
		if r.owner {
			r.priority = 255
		}
		return nil
	}
}

func WithAdvInterval(interval time.Duration) Option {
	return func(r *VirtualRouter) error {
		return r.setAdvInterval(interval)
	}
}

func (r *VirtualRouter) setAdvInterval(interval time.Duration) error {
	if interval < 10*time.Millisecond {
		return errors.New("interval can not less than 10 ms")
	}
	r.advertisementInterval = uint16(interval / (10 * time.Millisecond))
	return nil
}

func WithMasterAdvInterval(interval time.Duration) Option {
	return func(r *VirtualRouter) error {
		if interval < 10*time.Millisecond {
			return errors.New("interval can not less than 10 ms")
		}
		r.setMasterAdvInterval(uint16(interval / (10 * time.Millisecond)))
		return nil
	}
}

func WithPriority(priority byte) Option {
	return func(r *VirtualRouter) error {
		r.setPriority(priority)
		return nil
	}
}

func WithPreemtpMode(flag bool) Option {
	return func(r *VirtualRouter) error {
		r.setPreemptMode(flag)
		return nil
	}
}

func (r *VirtualRouter) setPreemptMode(flag bool) *VirtualRouter {
	r.preempt = flag
	return r
}

func WithIPvXAddr(ips ...net.IP) Option {
	return func(r *VirtualRouter) error {
		for _, v := range ips {
			r.addIPvXAddr(v)
		}
		return nil
	}
}

func (r *VirtualRouter) addIPvXAddr(ip net.IP) {
	var key [16]byte
	copy(key[:], ip)
	if _, ok := r.protectedIPAddrs[key]; ok {
		logger.Errorf("VirtualRouter.addIPvXAddr: add redundant IP addr %v", ip)
	} else {
		r.protectedIPAddrs[key] = true
	}
}

func defaultIFace() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("retrive interfaces: %w", err)
	}
	for _, v := range ifs {
		addrs, err := v.Addrs()
		if err != nil {
			logger.Warnf("retrive %v address: %w", v.Name, err)
			continue
		}
		for _, vv := range addrs {
			var ip net.IP
			switch vv := vv.(type) {
			case *net.IPNet:
				ip = vv.IP
			case *net.IPAddr:
				ip = vv.IP
			default:
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			return v.Name, nil
		}
	}
	return "", errors.New("no valid interface found")
}
