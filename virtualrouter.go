package vrrp

import (
	"fmt"
	"net"
	"time"
)

type VirtualRouter struct {
	id                            byte
	priority                      byte
	advertisementInterval         uint16
	advertisementIntervalOfMaster uint16
	skewTime                      uint16
	masterDownInterval            uint16
	preempt                       bool
	owner                         bool
	macAddressIPv4                net.HardwareAddr
	macAddressIPv6                net.HardwareAddr
	//
	netInterface        *net.Interface
	ipvX                byte
	preferredSourceIP   net.IP
	protectedIPAddrs    map[[16]byte]bool
	state               int
	ipLayerInterface    IPConnection
	ipAddrAnnouncer     AddrAnnouncer
	eventChannel        chan Event
	packetQueue         chan *VRRPPacket
	advertisementTicker *time.Ticker
	masterDownTimer     *time.Timer
	transitionsCh       chan Transition

	iface string
}

// NewVirtualRouter create a new virtual router with designated parameters
func NewVirtualRouter(opts ...Option) (*VirtualRouter, error) {
	vr := &VirtualRouter{}
	vr.id = 100
	vr.ipvX = IPv4

	vr.state = INIT
	vr.preempt = defaultPreempt
	if err := vr.setAdvInterval(defaultAdvertisementInterval); err != nil {
		return nil, fmt.Errorf("vr.setAdvInterval %w", err)
	}
	vr.setPriority(defaultPriority)
	vr.setMasterAdvInterval(uint16(defaultAdvertisementInterval / (10 * time.Millisecond)))
	// make
	vr.protectedIPAddrs = make(map[[16]byte]bool)
	vr.eventChannel = make(chan Event, EventChannelSize)
	vr.packetQueue = make(chan *VRRPPacket, PacketQueueSize)

	var err error
	vr.iface, err = defaultIFace()
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		if err := o(vr); err != nil {
			return nil, err
		}
	}
	networkInterface, err := net.InterfaceByName(vr.iface)
	if err != nil {
		return nil, fmt.Errorf("NewVirtualRouter: %w", err)
	}
	vr.netInterface = networkInterface
	// find preferred local IP address
	vr.preferredSourceIP, err = findIPByInterface(networkInterface, vr.ipvX)
	if err != nil {
		return nil, fmt.Errorf("NewVirtualRouter: %w", err)
	}
	vr.macAddressIPv4, _ = net.ParseMAC(fmt.Sprintf("00-00-5E-00-01-%X", vr.id))
	vr.macAddressIPv6, _ = net.ParseMAC(fmt.Sprintf("00-00-5E-00-02-%X", vr.id))
	if vr.ipvX == IPv4 {
		// set up ARP client
		vr.ipAddrAnnouncer, err = NewIPv4AddrAnnouncer(networkInterface)
		if err != nil {
			return nil, err
		}
		// set up IPv4 interface
		vr.ipLayerInterface, err = NewIPv4Conn(vr.preferredSourceIP, MultiAddrIPv4)
		if err != nil {
			return nil, err
		}
	} else {
		// set up ND client
		vr.ipAddrAnnouncer, err = NewIPv6AddrAnnouncer(networkInterface)
		if err != nil {
			return nil, err
		}
		// set up IPv6 interface
		vr.ipLayerInterface, err = NewIPv6Con(vr.preferredSourceIP, MultiAddrIPv6)
		if err != nil {
			return nil, err
		}
	}
	logger.Debugf("virtual router %v initialized, working on %v", vr.id, vr.iface)
	return vr, nil
}

func (r *VirtualRouter) setPriority(priority byte) *VirtualRouter {
	if r.owner {
		return r
	}
	r.priority = priority
	return r
}

func (r *VirtualRouter) setMasterAdvInterval(interval uint16) *VirtualRouter {
	r.advertisementIntervalOfMaster = interval
	r.skewTime = r.advertisementIntervalOfMaster - uint16(float32(r.advertisementIntervalOfMaster)*float32(r.priority)/256)
	r.masterDownInterval = 3*r.advertisementIntervalOfMaster + r.skewTime
	// 从MasterDownInterval和SkewTime的计算方式来看，同一组VirtualRouter中，Priority越高的Router越快地认为某个Master失效
	return r
}

func (r *VirtualRouter) removeIPvXAddr(ip net.IP) {
	var key [16]byte
	copy(key[:], ip)
	if _, ok := r.protectedIPAddrs[key]; ok {
		delete(r.protectedIPAddrs, key)
		logger.Debugf("IP %v removed", ip)
	} else {
		logger.Errorf("VirtualRouter.removeIPvXAddr: remove inexistent IP addr %v", ip)
	}
}

func (r *VirtualRouter) sendAdvertMessage() {
	for k := range r.protectedIPAddrs {
		logger.Debugf("send advert message of IP %v", net.IP(k[:]))
	}
	x, err := r.assembleVRRPPacket()
	if err != nil {
		logger.Errorf("VirtualRouter.assembleVRRPPacket: %v", err)
		return
	}
	if err := r.ipLayerInterface.WriteMessage(x); err != nil {
		logger.Errorf("VirtualRouter.WriteMessage: %v", err)
	}
}

// assembleVRRPPacket assemble vrrp advert packet
func (r *VirtualRouter) assembleVRRPPacket() (*VRRPPacket, error) {

	var packet VRRPPacket
	packet.SetPriority(r.priority)
	packet.SetVersion(VRRPv3)
	packet.SetVirtualRouterID(r.id)
	packet.SetAdvertisementInterval(r.advertisementInterval)
	packet.SetType()
	for k := range r.protectedIPAddrs {
		if err := packet.AddIPvXAddr(r.ipvX, net.IP(k[:])); err != nil {
			return nil, err
		}
	}
	var pshdr PseudoHeader
	pshdr.Protocol = IPProtocolNumber
	if r.ipvX == IPv4 {
		pshdr.DAddr = MultiAddrIPv4
	} else {
		pshdr.DAddr = MultiAddrIPv6
	}
	pshdr.Len = uint16(len(packet.ToBytes()))
	pshdr.SAddr = r.preferredSourceIP
	packet.SetCheckSum(&pshdr)
	return &packet, nil
}

// fetchVRRPPacket read vrrp packet from IP layer then push into Packet queue
func (r *VirtualRouter) fetchVRRPPacket() {
	for {
		packet, err := r.ipLayerInterface.ReadMessage()
		if err != nil {
			logger.Errorf("VirtualRouter.fetchVRRPPacket: %v", err)
			continue
		}
		if r.id == packet.GetVirtualRouterID() {
			r.packetQueue <- packet
			logger.Trace("VirtualRouter.fetchVRRPPacket: received one advertisement")
		} else {
			logger.Errorf("VirtualRouter.fetchVRRPPacket: received an advertisement with different ID: %v", packet.GetVirtualRouterID())
		}
	}
}

func (r *VirtualRouter) makeAdvertTicker() {
	r.advertisementTicker = time.NewTicker(time.Duration(r.advertisementInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) stopAdvertTicker() {
	r.advertisementTicker.Stop()
}

func (r *VirtualRouter) makeMasterDownTimer() {
	if r.masterDownTimer == nil {
		r.masterDownTimer = time.NewTimer(time.Duration(r.masterDownInterval*10) * time.Millisecond)
	} else {
		r.resetMasterDownTimer()
	}
}

func (r *VirtualRouter) stopMasterDownTimer() {
	if !r.masterDownTimer.Stop() {
		logger.Trace("master down timer expired before we stop it, drain the channel")
		select {
		case <-r.masterDownTimer.C:
		default:
		}
	} else {
		logger.Trace("master down timer stopped")
	}
}

func (r *VirtualRouter) resetMasterDownTimer() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.masterDownInterval*10) * time.Millisecond)
}

func (r *VirtualRouter) resetMasterDownTimerToSkewTime() {
	r.stopMasterDownTimer()
	r.masterDownTimer.Reset(time.Duration(r.skewTime*10) * time.Millisecond)
}

func (r *VirtualRouter) transitionDoWork(t Transition) {
	if r.transitionsCh == nil {
		logger.Debug("no transition channel: skipping %s", t)
		return
	}
	r.transitionsCh <- t
	logger.Debugf("transition [%s] sent", t)
	return
}

// ///////////////////////////////////////
func largerThan(ip1, ip2 net.IP) bool {
	if len(ip1) != len(ip2) {
		logger.Warn("largerThan: two compared IP addresses must have the same length")
		return false
	}
	for index := range ip1 {
		if ip1[index] > ip2[index] {
			return true
		} else if ip1[index] < ip2[index] {
			return false
		}
	}
	return false
}

// eventLoop vrrp event loop to handle various triggered events
func (r *VirtualRouter) eventLoop() {
	for {
		switch r.state {
		case INIT:
			select {
			case event := <-r.eventChannel:
				if event == EventStart {
					logger.Debugf("event %v received", event)
					if r.priority == 255 || r.owner {
						logger.Debugf("enter owner mode")
						r.sendAdvertMessage()
						if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
							logger.Errorf("VirtualRouter.EventLoop: %v", err)
						}
						// set up advertisement timer
						r.makeAdvertTicker()
						logger.Debug("enter MASTER state")
						r.state = MASTER
						r.transitionDoWork(Init2Master)
					} else {
						logger.Debugf("VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						// set up master down timer
						r.makeMasterDownTimer()
						logger.Debug("enter BACKUP state")
						r.state = BACKUP
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case MASTER:
			// check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event != EventShutdown {
					continue
				}
				// close advert timer
				r.stopAdvertTicker()
				// send advertisement with priority 0
				priority := r.priority
				r.setPriority(0)
				r.sendAdvertMessage()
				r.setPriority(priority)
				// transition into INIT
				r.state = INIT
				r.transitionDoWork(Master2Init)
				logger.Debugf("event %v received", event)
				// maybe we can break out the event loop
				return
			case <-r.advertisementTicker.C: // check if advertisement timer fired
				r.sendAdvertMessage()
			default:
				// nothing to do, just break
			}
			// process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					// I don't think we should anything here
					continue
				}
				if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.SAddr, r.preferredSourceIP)) {

					// cancel Advertisement timer
					r.stopAdvertTicker()
					// set up master down timer
					r.setMasterAdvInterval(packet.GetAdvertisementInterval())
					r.makeMasterDownTimer()
					r.state = BACKUP
					r.transitionDoWork(Master2Backup)
				} else {
					// just discard this one
				}
			default:
				// nothing to do
			}
		case BACKUP:
			select {
			case event := <-r.eventChannel:
				if event != EventShutdown {
					continue
				}
				// close master down timer
				r.stopMasterDownTimer()
				// transition into INIT
				r.state = INIT
				r.transitionDoWork(Backup2Init)
				logger.Debugf("event %s received", event)
			default:
			}
			// process incoming advertisement
			select {
			case packet := <-r.packetQueue:
				if packet.GetPriority() == 0 {
					logger.Debugf("received an advertisement with priority 0, transit into MASTER state", r.id)
					// Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
					continue
				}
				if !r.preempt || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.SAddr, r.preferredSourceIP)) {
					// reset master down timer
					r.setMasterAdvInterval(packet.GetAdvertisementInterval())
					r.resetMasterDownTimer()
				} else {
					// nothing to do, just discard this one
				}
			default:
				// nothing to do
			}
			select {
			// Master_Down_Timer fired
			case <-r.masterDownTimer.C:
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
					logger.Errorf("VirtualRouter.EventLoop: %v", err)
				}
				// Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()

				r.state = MASTER
				r.transitionDoWork(Backup2Master)
			default:
				// nothing to do
			}

		}
	}
}

// eventSelector vrrp event selector to handle various triggered events
func (r *VirtualRouter) eventSelector() {
	for {
		switch r.state {
		case INIT:
			select {
			case event := <-r.eventChannel:
				if event == EventStart {
					logger.Debugf("event %v received", event)
					if r.priority == 255 || r.owner {
						logger.Debugf("enter owner mode")
						r.sendAdvertMessage()
						if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
							logger.Errorf("VirtualRouter.EventLoop: %v", err)
						}
						// set up advertisement timer
						r.makeAdvertTicker()

						logger.Debug("enter MASTER state")
						r.state = MASTER
						r.transitionDoWork(Init2Master)
					} else {
						logger.Debugf("VR is not the owner of protected IP addresses")
						r.setMasterAdvInterval(r.advertisementInterval)
						// set up master down timer
						r.makeMasterDownTimer()
						logger.Debug("enter BACKUP state")
						r.state = BACKUP
						r.transitionDoWork(Init2Backup)
					}
				}
			}
		case MASTER:
			// check if shutdown event received
			select {
			case event := <-r.eventChannel:
				if event == EventShutdown {
					// close advert timer
					r.stopAdvertTicker()
					// send advertisement with priority 0
					priority := r.priority
					r.setPriority(0)
					r.sendAdvertMessage()
					r.setPriority(priority)
					// transition into INIT
					r.state = INIT
					r.transitionDoWork(Master2Init)
					logger.Debugf("event %v received", event)
					// maybe we can break out the event loop
					return
				}
			case <-r.advertisementTicker.C: // check if advertisement timer fired
				r.sendAdvertMessage()
			case packet := <-r.packetQueue: // process incoming advertisement
				if packet.GetPriority() == 0 {
					// I don't think we should anything here
					continue
				}
				if packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.SAddr, r.preferredSourceIP)) {

					// cancel Advertisement timer
					r.stopAdvertTicker()
					// set up master down timer
					r.setMasterAdvInterval(packet.GetAdvertisementInterval())
					r.makeMasterDownTimer()
					r.state = BACKUP
					r.transitionDoWork(Master2Backup)
				} else {
					// just discard this one
				}
			}

		case BACKUP:
			select {
			case event := <-r.eventChannel:
				if event == EventShutdown {
					// close master down timer
					r.stopMasterDownTimer()
					// transition into INIT
					r.state = INIT
					r.transitionDoWork(Backup2Init)
					logger.Debugf("event %s received", event)
				}
			case packet := <-r.packetQueue: // process incoming advertisement
				if packet.GetPriority() == 0 {
					logger.Debugf("received an advertisement with priority 0, transit into MASTER state %v", r.id)
					// Set the Master_Down_Timer to Skew_Time
					r.resetMasterDownTimerToSkewTime()
					continue
				}
				if !r.preempt || packet.GetPriority() > r.priority || (packet.GetPriority() == r.priority && largerThan(packet.Pshdr.SAddr, r.preferredSourceIP)) {
					// reset master down timer
					r.setMasterAdvInterval(packet.GetAdvertisementInterval())
					r.resetMasterDownTimer()
				} else {
					// nothing to do, just discard this one
				}
			case <-r.masterDownTimer.C: // Master_Down_Timer fired
				// Send an ADVERTISEMENT
				r.sendAdvertMessage()
				if err := r.ipAddrAnnouncer.AnnounceAll(r); err != nil {
					logger.Errorf("VirtualRouter.EventLoop: %v", err)
				}
				// Set the Advertisement Timer to Advertisement interval
				r.makeAdvertTicker()
				r.state = MASTER
				r.transitionDoWork(Backup2Master)
			}

		}
	}
}

func (r *VirtualRouter) StartWithEventLoop() {
	go r.fetchVRRPPacket()
	go func() {
		r.eventChannel <- EventStart
	}()
	r.eventLoop()
}

func (r *VirtualRouter) StartWithEventSelector(ch chan Transition) {
	if ch != nil {
		r.transitionsCh = ch
	}
	go r.fetchVRRPPacket()
	go func() {
		r.eventChannel <- EventStart
	}()
	r.eventSelector()
}

func (r *VirtualRouter) Stop() {
	r.eventChannel <- EventShutdown
}
