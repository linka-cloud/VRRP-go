package vrrp

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

type IPConnection interface {
	WriteMessage(*VRRPPacket) error
	ReadMessage() (*VRRPPacket, error)
}

type AddrSpeaker interface {
	AddrAnnouncer
	AddrResponder
}

type AddrAnnouncer interface {
	AnnounceAll(vr *VirtualRouter) error
}

type AddrResponder interface {
	Respond(ctx context.Context, vr *VirtualRouter) error
}

func ipConnection(local, remote net.IP) (*net.IPConn, error) {

	var conn *net.IPConn
	var err error
	// redundant
	// todo simplify here
	if local.IsLinkLocalUnicast() {
		itf, err := findInterfaceByIP(local)
		if err != nil {
			return nil, fmt.Errorf("ipConnection: can't find zone info of %v", local)
		}
		conn, err = net.ListenIP("ip:112", &net.IPAddr{IP: local, Zone: itf.Name})
	} else {
		conn, err = net.ListenIP("ip:112", &net.IPAddr{IP: local})
	}
	if err != nil {
		return nil, err
	}
	fd, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if remote.To4() != nil {
		// IPv4 mode
		// set hop limit
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, MultiTTL); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		// set tos
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, 7); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		// disable multicast loop
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
	} else {
		// IPv6 mode
		// set hop limit
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		// disable multicast loop
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, 0); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		// to receive the hop limit and dst address in oob
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_2292HOPLIMIT, 1); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}
		if err := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_2292PKTINFO, 1); err != nil {
			return nil, fmt.Errorf("ipConnection: %v", err)
		}

	}
	logger.Debugf("IP virtual connection established %v ==> %v", local, remote)
	return conn, nil
}

func findIPByInterface(itf *net.Interface, IPvX byte) (net.IP, error) {
	addrs, err := itf.Addrs()
	if err != nil {
		return nil, fmt.Errorf("findIPByInterface: %v", err)
	}
	for index := range addrs {
		ipaddr, _, err := net.ParseCIDR(addrs[index].String())
		if err != nil {
			return nil, fmt.Errorf("findIPByInterface: %v", err)
		}
		if IPvX == IPv4 {
			if ipaddr.To4() != nil {
				if ipaddr.IsGlobalUnicast() {
					return ipaddr, nil
				}
			}
		} else {
			if ipaddr.To4() == nil {
				if ipaddr.IsLinkLocalUnicast() {
					return ipaddr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("findIPByInterface: can not find valid IP addrs on %v", itf.Name)
}

func findInterfaceByIP(ip net.IP) (*net.Interface, error) {
	itfs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("findInterfaceByIP: %v", err)
	}
	for index := range itfs {
		addrs, err := itfs[index].Addrs()
		if err != nil {
			return nil, fmt.Errorf("findInterfaceByIP: %v", err)
		}
		for index1 := range addrs {
			ipaddr, _, err := net.ParseCIDR(addrs[index1].String())
			if err != nil {
				return nil, fmt.Errorf("findInterfaceByIP: %v", err)
			}
			if ipaddr.Equal(ip) {
				return &itfs[index], nil
			}
		}

	}

	return nil, fmt.Errorf("findInterfaceByIP: can't find the corresponding interface of %v", ip)
}
