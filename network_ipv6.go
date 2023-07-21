package vrrp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/mdlayher/ndp"
)

var (
	_ AddrSpeaker  = (*IPv6AddrAnnouncer)(nil)
	_ IPConnection = (*IPv6Con)(nil)
)

type IPv6AddrAnnouncer struct {
	con *ndp.Conn
}

func NewIPv6AddrAnnouncer(nif *net.Interface) (*IPv6AddrAnnouncer, error) {
	con, ip, err := ndp.Listen(nif, ndp.LinkLocal)
	if err != nil {
		return nil, fmt.Errorf("NewIPv6AddrAnnouncer: %w", err)
	}
	logger.Infof("NDP client initialized, working on %v, source IP %v", nif.Name, ip)
	return &IPv6AddrAnnouncer{con: con}, nil
}

func (nd *IPv6AddrAnnouncer) AnnounceAll(vr *VirtualRouter) error {
	for key := range vr.protectedIPAddrs {
		multicastgroup, err := ndp.SolicitedNodeMulticast(key[:])
		if err != nil {
			logger.Errorf("IPv6AddrAnnouncer.AnnounceAll: %v", err)
			return err
		}
		// send unsolicited NeighborAdvertisement to refresh link layer address cache
		msg := &ndp.NeighborAdvertisement{
			Override:      true,
			TargetAddress: net.IP(key[:]),
			Options: []ndp.Option{
				&ndp.LinkLayerAddress{
					Direction: ndp.Source,
					Addr:      vr.netInterface.HardwareAddr,
				},
			},
		}
		if err := nd.con.WriteTo(msg, nil, multicastgroup); err != nil {
			logger.Errorf("IPv6AddrAnnouncer.AnnounceAll: %v", err)
			return err
		}
		logger.Infof("send unsolicited neighbor advertisement for %v", net.IP(key[:]))
	}

	return nil
}

func (nd *IPv6AddrAnnouncer) Respond(ctx context.Context, vr *VirtualRouter) error {
	return errors.New("unimplemented")
}

type IPv6Con struct {
	buffer []byte
	oob    []byte
	remote net.IP
	local  net.IP
	Con    *net.IPConn
}

func NewIPv6Con(local, remote net.IP) (*IPv6Con, error) {
	con, err := ipConnection(local, remote)
	if err != nil {
		return nil, fmt.Errorf("NewIPv6Con: %w", err)
	}
	if err := joinIPv6MulticastGroup(con, local, remote); err != nil {
		return nil, fmt.Errorf("NewIPv6Con: %v", err)
	}
	return &IPv6Con{
		buffer: make([]byte, 4096),
		oob:    make([]byte, 4096),
		local:  local,
		remote: remote,
		Con:    con,
	}, nil
}

func (con *IPv6Con) WriteMessage(packet *VRRPPacket) error {
	if _, err := con.Con.WriteToIP(packet.ToBytes(), &net.IPAddr{IP: con.remote}); err != nil {
		return fmt.Errorf("IPv6Con.WriteMessage: %v", err)
	}
	return nil
}

func (con *IPv6Con) ReadMessage() (*VRRPPacket, error) {
	buffern, oobn, _, raddr, err := con.Con.ReadMsgIP(con.buffer, con.oob)
	if err != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", err)
	}
	oobdata, err := syscall.ParseSocketControlMessage(con.oob[:oobn])
	if err != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", err)
	}
	var (
		dst    net.IP
		ttl    byte
		getTTL = false
	)
	for index := range oobdata {
		if oobdata[index].Header.Level != syscall.IPPROTO_IPV6 {
			continue
		}
		switch oobdata[index].Header.Type {
		case syscall.IPV6_2292HOPLIMIT:
			if len(oobdata[index].Data) == 0 {
				return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid HOPLIMIT")
			}
			ttl = oobdata[index].Data[0]
			getTTL = true
		case syscall.IPV6_2292PKTINFO:
			if len(oobdata[index].Data) < 16 {
				return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid destination IP addrress length")
			}
			dst = oobdata[index].Data[:16]
		}
	}
	if !getTTL {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: HOPLIMIT not found")
	}
	if dst == nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: destination address not found")
	}
	pshdr := PseudoHeader{
		DAddr:    dst,
		SAddr:    raddr.IP,
		Protocol: IPProtocolNumber,
		Len:      uint16(buffern),
	}
	advertisement, err := FromBytes(IPv6, con.buffer)
	if err != nil {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: %v", err)
	}
	if ttl != 255 {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid HOPLIMIT")
	}
	if Version(advertisement.GetVersion()) != VRRPv3 {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid vrrp version %v", advertisement.GetVersion())
	}
	if !advertisement.ValidateCheckSum(&pshdr) {
		return nil, fmt.Errorf("IPv6Con.ReadMessage: invalid check sum")
	}
	advertisement.Pshdr = &pshdr
	return advertisement, nil
}

func joinIPv6MulticastGroup(con *net.IPConn, local, remote net.IP) error {
	fd, err := con.File()
	if err != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", err)
	}
	defer fd.Close()
	mreq := &syscall.IPv6Mreq{}
	copy(mreq.Multiaddr[:], remote.To16())
	iface, err := findInterfaceByIP(local)
	if err != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", err)
	}
	mreq.Interface = uint32(iface.Index)
	if err := syscall.SetsockoptIPv6Mreq(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq); err != nil {
		return fmt.Errorf("joinIPv6MulticastGroup: %v", err)
	}
	logger.Infof("Join IPv6 multicast group %v on %v", remote, iface.Name)
	return nil
}
