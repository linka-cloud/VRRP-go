package vrrp

import (
	"net"
	"time"
)

type Version byte

const (
	VRRPv1 Version = 1
	VRRPv2 Version = 2
	VRRPv3 Version = 3
)

func (v Version) String() string {
	switch v {
	case VRRPv1:
		return "VRRPVersion1"
	case VRRPv2:
		return "VRRPVersion2"
	case VRRPv3:
		return "VRRPVersion3"
	default:
		return "unknown version"
	}
}

const (
	IPv4 = 4
	IPv6 = 6
)

const (
	INIT = iota
	MASTER
	BACKUP
)

const (
	MultiTTL         = 255
	IPProtocolNumber = 112
)

var MultiAddrIPv4 = net.IPv4(224, 0, 0, 18)
var MultiAddrIPv6 = net.ParseIP("FF02:0:0:0:0:0:0:12")

var BroadcastHADDR, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

type Event byte

const (
	EventShutdown Event = iota
	EventStart
)

func (e Event) String() string {
	switch e {
	case EventStart:
		return "start"
	case EventShutdown:
		return "shutdown"
	default:
		return "unknown event"
	}
}

const PacketQueueSize = 1000
const EventChannelSize = 1

type Transition int

func (t Transition) String() string {
	switch t {
	case Master2Backup:
		return "master to backup"
	case Backup2Master:
		return "backup to master"
	case Init2Master:
		return "init to master"
	case Init2Backup:
		return "init to backup"
	case Backup2Init:
		return "backup to init"
	case Master2Init:
		return "master to init"
	default:
		return "unknown transition"
	}
}

const (
	Master2Backup Transition = iota
	Backup2Master
	Init2Master
	Init2Backup
	Master2Init
	Backup2Init
)

var (
	defaultPreempt                    = true
	defaultPriority              byte = 100
	defaultAdvertisementInterval      = 1 * time.Second
)
