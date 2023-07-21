package vrrp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/sirupsen/logrus"
)

var (
	_ AddrAnnouncer = (*IPv4AddrAnnouncer)(nil)
	_ IPConnection  = (*IPv4Con)(nil)
)

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
	for k := range vr.protectedIPAddrs {
		if err := ar.announce(net.IP(k[:]).To4(), vr.netInterface.HardwareAddr); err != nil {
			return fmt.Errorf("IPv4AddrAnnouncer.AnnounceAll: %v", err)
		}
	}
	return nil
}

func (ar *IPv4AddrAnnouncer) announce(ip net.IP, hwd net.HardwareAddr) error {
	if err := ar.arpc.SetWriteDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		return fmt.Errorf("IPv4AddrAnnouncer.announce: %v", err)
	}
	packet := ar.makeGratuitousPacket()
	packet.SenderHardwareAddr = hwd
	packet.SenderIP = ip.To4()
	packet.TargetHardwareAddr = BroadcastHADDR
	packet.TargetIP = ip.To4()
	logger.Debugf("send gratuitous arp for %v", ip)
	if err := ar.arpc.WriteTo(packet, BroadcastHADDR); err != nil {
		return fmt.Errorf("IPv4AddrAnnouncer.announce: %v", err)
	}
	return nil
}

func (ar *IPv4AddrAnnouncer) Respond(ctx context.Context, vr *VirtualRouter) error {
	tk := time.NewTicker(time.Second)
	errs := make(chan error, 1)
	go func() {
		errs <- ar.process(ctx, vr)
	}()
	for {
		select {
		case <-tk.C:
			logger.Debug("ARP Annoncer: announcing virtual router ips")
			if err := ar.AnnounceAll(vr); err != nil {
				logger.WithError(err).Error("ARP Annoncer failed")
			}
		case err := <-errs:
			logger.WithError(err).Error("ARP Responder failed")
			return err
		case <-ctx.Done():
			// logger.WithError(ctx.Err()).Error("ARP Responder stopped")
			return ctx.Err()
		}
	}
}

func (ar *IPv4AddrAnnouncer) process(ctx context.Context, vr *VirtualRouter) error {
	for {
		pkt, eth, err := ar.arpc.Read()
		if err != nil {
			logger.WithError(err).Error("ARP Responder read failed")
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logger.Debugf("ARP Responder request: %s", pkt.TargetIP)
		// Ignore ARP replies.
		if pkt.Operation != arp.OperationRequest {
			continue
		}
		// Ignore ARP requests which are not broadcast or bound directly for this machine.
		if !bytes.Equal(eth.Destination, ethernet.Broadcast) && !bytes.Equal(eth.Destination, vr.netInterface.HardwareAddr) {
			continue
		}
		found := false
		for ip := range vr.protectedIPAddrs {
			if bytes.Equal(pkt.TargetIP, net.IP(ip[:]).To4()) {
				found = true
				break
			}
		}
		if !found {
			logger.WithField("targetIP", pkt.TargetIP.String()).Debugf("skipping response")
			continue
		}
		// Ignore ARP requests that the announcer tells us to ignore.
		if err := ar.announce(pkt.TargetIP, vr.netInterface.HardwareAddr); err != nil {
			return err
		}

		logger.WithFields(logrus.Fields{
			"interface":   vr.iface,
			"ip":          pkt.TargetIP,
			"senderIP":    pkt.SenderIP,
			"senderMAC":   pkt.SenderHardwareAddr,
			"responseMAC": vr.netInterface.HardwareAddr,
		}).Debug("got ARP request for service IP, sending response")

		if err := ar.arpc.Reply(pkt, vr.netInterface.HardwareAddr, pkt.TargetIP); err != nil {
			logger.WithFields(logrus.Fields{
				"op":          "arpReply",
				"interface":   vr.iface,
				"ip":          pkt.TargetIP,
				"senderIP":    pkt.SenderIP,
				"senderMAC":   pkt.SenderHardwareAddr,
				"responseMAC": vr.netInterface.HardwareAddr,
				"error":       err,
			}).Error("failed to send ARP reply")
		}
	}
}

type IPv4Con struct {
	buffer     []byte
	remote     net.IP
	local      net.IP
	SendCon    *net.IPConn
	ReceiveCon *net.IPConn
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
