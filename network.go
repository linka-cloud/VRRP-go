package vrrp

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ndp"
)

type IPConnection interface {
	WriteMessage(*VRRPPacket) error
	ReadMessage() (*VRRPPacket, error)
}

type AddrAnnouncer interface {
	AnnounceAll(vr *VirtualRouter) error
}

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

type IPv4AddrAnnouncer struct {
	arpc *arp.Client
}

func NewIPv4AddrAnnouncer(nif *net.Interface) (*IPv4AddrAnnouncer, error) {
	aar, err := arp.Dial(nif)
	if err != nil {
		return nil, err
	}
	logger.Debug("IPv4 addresses announcer created")
	return &IPv4AddrAnnouncer{arpc: aar}, nil
}

// makeGratuitousPacket make gratuitous ARP packet with out payload
func (ar *IPv4AddrAnnouncer) makeGratuitousPacket() *arp.Packet {
	return &arp.Packet{
		HardwareType:       1,      // ethernet10m
		ProtocolType:       0x0800, // IPv4
		HardwareAddrLength: 6,
		IPLength:           4,
		Operation:          2, // response
	}
}

// AnnounceAll send gratuitous ARP response for all protected IPv4 addresses
func (ar *IPv4AddrAnnouncer) AnnounceAll(vr *VirtualRouter) error {
	if err := ar.arpc.SetWriteDeadline(time.Now().Add(500 * time.Microsecond)); err != nil {
		return fmt.Errorf("IPv4AddrAnnouncer.AnnounceAll: %v", err)
	}
	packet := ar.makeGratuitousPacket()
	for k := range vr.protectedIPAddrs {
		packet.SenderHardwareAddr = vr.netInterface.HardwareAddr
		packet.SenderIP = net.IP(k[:]).To4()
		packet.TargetHardwareAddr = BroadcastHADDR
		packet.TargetIP = net.IP(k[:]).To4()
		logger.Debugf("send gratuitous arp for %v", net.IP(k[:]))
		if err := ar.arpc.WriteTo(packet, BroadcastHADDR); err != nil {
			return fmt.Errorf("IPv4AddrAnnouncer.AnnounceAll: %v", err)
		}
	}
	return nil
}

type IPv4Con struct {
	buffer     []byte
	remote     net.IP
	local      net.IP
	SendCon    *net.IPConn
	ReceiveCon *net.IPConn
}

type IPv6Con struct {
	buffer []byte
	oob    []byte
	remote net.IP
	local  net.IP
	Con    *net.IPConn
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

func makeMulticastIPv4Conn(multi, local net.IP) (*net.IPConn, error) {
	conn, err := net.ListenIP("ip4:112", &net.IPAddr{IP: multi})
	if err != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", err)
	}
	fd, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", err)
	}
	defer fd.Close()
	multi = multi.To4()
	local = local.To4()
	mreq := &syscall.IPMreq{
		Multiaddr: [4]byte{multi[0], multi[1], multi[2], multi[3]},
		Interface: [4]byte{local[0], local[1], local[2], local[3]},
	}
	if err := syscall.SetsockoptIPMreq(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); err != nil {
		return nil, fmt.Errorf("makeMulticastIPv4Conn: %v", err)
	}
	return conn, nil
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

func NewIPv4Conn(local, remote net.IP) (IPConnection, error) {
	sendConn, err := ipConnection(local, remote)
	if err != nil {
		return nil, err
	}
	receiveConn, err := makeMulticastIPv4Conn(MultiAddrIPv4, local)
	if err != nil {
		return nil, err
	}
	return &IPv4Con{
		buffer:     make([]byte, 2048),
		local:      local,
		remote:     remote,
		SendCon:    sendConn,
		ReceiveCon: receiveConn,
	}, nil
}

func (conn *IPv4Con) WriteMessage(packet *VRRPPacket) error {
	if _, err := conn.SendCon.WriteTo(packet.ToBytes(), &net.IPAddr{IP: conn.remote}); err != nil {
		return fmt.Errorf("IPv4Con.WriteMessage: %v", err)
	}
	return nil
}

func (conn *IPv4Con) ReadMessage() (*VRRPPacket, error) {
	n, err := conn.ReceiveCon.Read(conn.buffer)
	if err != nil {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: %v", err)
	}
	if n < 20 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: IP datagram lenght %v too small", n)
	}
	hdrlen := (int(conn.buffer[0]) & 0x0f) << 2
	if hdrlen > n {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: the header length %v is lagger than total length %V", hdrlen, n)
	}
	if conn.buffer[8] != 255 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: the TTL of IP datagram carring vrrp advertisment must equal to 255")
	}
	advertisement, err := FromBytes(IPv4, conn.buffer[hdrlen:n])
	if err != nil {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: %v", err)
	}
	if Version(advertisement.GetVersion()) != VRRPv3 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: received an advertisement with %s", Version(advertisement.GetVersion()))
	}
	pshdr := PseudoHeader{
		SAddr:    net.IPv4(conn.buffer[12], conn.buffer[13], conn.buffer[14], conn.buffer[15]).To16(),
		DAddr:    net.IPv4(conn.buffer[16], conn.buffer[17], conn.buffer[18], conn.buffer[19]).To16(),
		Protocol: IPProtocolNumber,
		Len:      uint16(n - hdrlen),
	}
	if !advertisement.ValidateCheckSum(&pshdr) {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: validate the check sum of advertisement failed")
	}
	advertisement.Pshdr = &pshdr
	return advertisement, nil
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
	if getTTL == false {
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
