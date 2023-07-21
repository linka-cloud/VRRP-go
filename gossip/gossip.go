package gossip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/sirupsen/logrus"
)

func Resolve(service, proto, name string) ([]string, error) {
	_, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil {
		return nil, err
	}
	var records []string
	for _, addr := range addrs {
		ips, err := net.LookupIP(addr.Target)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			continue
		}
		for _, v := range ips {
			address := v.String()
			if addr.Port > 0 {
				address = fmt.Sprintf("%s:%d", address, addr.Port)
			}
			records = append(records, address)
		}
	}
	return records, nil
}

var _ memberlist.Broadcast = &broadcast{}

type broadcast struct {
	msg []byte
}

func (b *broadcast) Invalidates(_ memberlist.Broadcast) bool { return false }
func (b *broadcast) Message() []byte                         { return b.msg }
func (b *broadcast) UniqueBroadcast()                        {}
func (b *broadcast) Finished()                               {}

func hash(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

var _ memberlist.Delegate = (*delegate)(nil)

type delegate struct {
	ctx    context.Context
	q      memberlist.TransmitLimitedQueue
	ch     chan []byte
	mu     sync.RWMutex
	seen   map[string]time.Time
	maxAge time.Duration
}

func (d *delegate) NodeMeta(_ int) []byte {
	return nil
}

func (d *delegate) Send(msg []byte) {
	d.mu.Lock()
	d.seen[hash(msg)] = time.Now()
	d.mu.Unlock()
	d.q.QueueBroadcast(&broadcast{msg: msg})
}

func (d *delegate) NotifyMsg(bytes []byte) {
	h := hash(bytes)
	d.mu.RLock()
	_, ok := d.seen[h]
	d.mu.RUnlock()
	if ok {
		return
	}
	d.mu.Lock()
	d.seen[h] = time.Now()
	d.mu.Unlock()
	b := make([]byte, len(bytes))
	copy(b, bytes)
	d.q.QueueBroadcast(&broadcast{msg: b})
	d.ch <- bytes
	d.clean()
}

func (d *delegate) clean() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range d.seen {
		if time.Since(v) > d.maxAge {
			delete(d.seen, k)
		}
	}
}

func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.q.GetBroadcasts(overhead, limit)
}

func (d *delegate) LocalState(_ bool) []byte {
	return nil
}

func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	logrus.Infof("merge remote state: %s (%v)", string(buf), join)
}

func (d *delegate) Read(ctx context.Context) ([]byte, error) {
	select {
	case <-d.ctx.Done():
		return nil, fmt.Errorf("transport: %w", d.ctx.Err())
	case msg := <-d.ch:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type Transport struct {
	list     *memberlist.Memberlist
	delegate *delegate
}

func (t *Transport) Read(ctx context.Context) ([]byte, error) {
	return t.delegate.Read(ctx)
}

func (t *Transport) Write(ctx context.Context, msg []byte) error {
	t.delegate.Send(msg)
	return nil
}

func NewTransport(ctx context.Context, name string, ip string, port int, interval time.Duration, addrs ...string) (t *Transport, err error) {
	config := memberlist.DefaultWANConfig()
	config.BindPort = port
	if name == "" {
		name, err = os.Hostname()
		if err != nil {
			return nil, err
		}
	}
	config.Name = name
	config.AdvertiseAddr = ip
	config.AdvertisePort = port
	config.GossipInterval = interval
	t = &Transport{
		delegate: &delegate{
			ctx: ctx,
			q: memberlist.TransmitLimitedQueue{
				RetransmitMult: config.RetransmitMult,
			},
			ch:     make(chan []byte, 10),
			seen:   make(map[string]time.Time),
			maxAge: 5 * time.Second,
		},
	}
	config.Delegate = t.delegate
	t.list, err = memberlist.Create(config)
	if err != nil {
		return nil, err
	}
	t.delegate.q.NumNodes = t.list.NumMembers
	if _, err = t.list.Join(addrs); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) Close() error {
	return t.list.Leave(time.Second)
}
