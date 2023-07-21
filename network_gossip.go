package vrrp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go.linka.cloud/vrrp-go/gossip"
)

var _ IPConnection = (*Gossip)(nil)

type Gossip struct {
	t      *gossip.Transport
	ipv    byte
	ip     net.IP
	remote net.IP
}

type msg struct {
	PseudoHeader
	Payload []byte
	Time    time.Time
}

func (g *Gossip) WriteMessage(packet *VRRPPacket) error {
	p := packet.ToBytes()
	msg := &msg{
		PseudoHeader: PseudoHeader{
			SAddr:    g.ip.To16(),
			DAddr:    g.remote.To16(),
			Protocol: IPProtocolNumber,
			Len:      uint16(len(p)),
		},
		Time:    time.Now(),
		Payload: p,
	}
	b := bytes.NewBuffer(nil)
	b.Write(msg.PseudoHeader.ToBytes())
	if err := binary.Write(b, binary.LittleEndian, msg.Time.UnixMilli()); err != nil {
		return fmt.Errorf("Gossip.WriteMessage: %v", err)
	}
	b.Write(msg.Payload)
	return g.t.Write(context.Background(), b.Bytes())
}

func (g *Gossip) ReadMessage() (*VRRPPacket, error) {
	b, err := g.t.Read(context.Background())
	if err != nil {
		return nil, err
	}
	if len(b) < 44 {
		return nil, fmt.Errorf("Gossip.ReadMessage: message lenght %v too small", len(b))
	}
	m := &msg{
		PseudoHeader: PseudoHeader{
			SAddr:    b[:16],
			DAddr:    b[16:32],
			Zero:     b[32],
			Protocol: b[33],
			Len:      binary.BigEndian.Uint16(b[34:36]),
		},
		Time:    time.UnixMilli(int64(binary.LittleEndian.Uint64(b[36:44]))),
		Payload: b[44:],
	}
	if len(m.Payload) != int(m.Len) {
		return nil, fmt.Errorf("Gossip.ReadMessage: message lenght field %v does not match payload length %v", m.Len, len(m.Payload))
	}
	// logrus.Infof("time since sent: %v", time.Since(m.Time))
	advertisement, err := FromBytes(IPv4, m.Payload)
	if err != nil {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: %v", err)
	}
	if Version(advertisement.GetVersion()) != VRRPv3 {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: received an advertisement with %s", Version(advertisement.GetVersion()))
	}
	if !advertisement.ValidateCheckSum(&m.PseudoHeader) {
		return nil, fmt.Errorf("IPv4Con.ReadMessage: validate the check sum of advertisement failed")
	}
	advertisement.Pshdr = &m.PseudoHeader
	return advertisement, nil
}

func NewGossip(ipv byte, ip net.IP, remote net.IP, port int, interval time.Duration, addrs ...string) (*Gossip, error) {
	t, err := gossip.NewTransport(context.Background(), "", ip.String(), port, interval, addrs...)
	if err != nil {
		return nil, err
	}
	return &Gossip{t: t, ipv: ipv, ip: ip, remote: remote}, nil
}
