package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"

	vrrp "go.linka.cloud/vrrp-go"
)

var (
	vrid     int
	priority int
	iface    string
)

func init() {
	flag.IntVar(&vrid, "vrid", 233, "virtual router id")
	flag.IntVar(&priority, "pri", 100, "router priority")
	flag.StringVar(&iface, "iface", "eth0", "network interface")
}

func main() {
	log := logrus.StandardLogger()
	flag.Parse()
	vrrp.SetLogLevel(logrus.InfoLevel)
	vr, err := vrrp.NewVirtualRouter(byte(vrid), iface, false, vrrp.IPv4)
	if err != nil {
		log.Fatal(err)
	}
	if err := vr.SetAdvInterval(100 * time.Millisecond); err != nil {
		logrus.Fatal(err)
	}
	if err := vr.SetPriorityAndMasterAdvInterval(byte(priority), time.Millisecond*100); err != nil {
		log.Fatal(err)
	}
	handle := func(t vrrp.Transition) {
		switch t {
		case vrrp.Backup2Master:
			log.Info("init to master")
		case vrrp.Master2Init:
			log.Info("master to init")
		case vrrp.Master2Backup:
			log.Info("master to backup")
		}
	}
	ch := make(chan vrrp.Transition, 10)
	go vr.StartWithEventSelector(ch)
	sigs := make(chan os.Signal)
	signal.Notify(sigs, os.Kill, os.Interrupt)
	for {
		select {
		case t := <-ch:
			handle(t)
		case s := <-sigs:
			fmt.Println()
			log.Warnf("received: %v", s)
			log.Warn("exiting...")
			vr.Stop()
			os.Exit(1)
		}
	}

}
