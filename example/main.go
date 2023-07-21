package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"go.linka.cloud/vrrp-go"
)

var (
	vrid     int
	priority int
	iface    string
	preemt   bool
	logLvl   string

	gossipPort  int
	gossipAddrs string
)

func init() {
	flag.IntVar(&vrid, "vrid", 233, "virtual router id")
	flag.IntVar(&priority, "pri", 100, "router priority")
	flag.StringVar(&iface, "iface", "eth0", "network interface")
	flag.BoolVar(&preemt, "preempt", false, "set preempt mode")
	flag.StringVar(&logLvl, "log", "INFO", "log level: DEBUG|INFO|WARN|ERROR")
	flag.IntVar(&gossipPort, "gossip-port", 0, "gossip port")
	flag.StringVar(&gossipAddrs, "gossip-addrs", "", "gossip addresses")
}

func main() {
	vips := []string{"172.42.0.42", "172.42.0.43"}
	log := logrus.StandardLogger()
	flag.Parse()
	if lvl, err := logrus.ParseLevel(logLvl); err == nil {
		vrrp.SetLogLevel(lvl)
	} else {
		logrus.Warnf("invalid log level: %v, using INFO level", logLvl)
		vrrp.SetLogLevel(logrus.InfoLevel)
	}
	var ips []net.IP
	for _, v := range vips {
		ips = append(ips, net.ParseIP(v))
	}
	var addrs []string
	if gossipPort > 0 {
		addrs = strings.Split(gossipAddrs, ",")
	}
	interval := 500 * time.Millisecond
	vr, err := vrrp.NewVirtualRouter(
		vrrp.WithVRID(byte(vrid)),
		vrrp.WithInterface(iface),
		vrrp.WithAdvInterval(interval),
		vrrp.WithPriority(byte(priority)),
		vrrp.WithMasterAdvInterval(interval),
		vrrp.WithPreemtpMode(preemt),
		vrrp.WithIPvXAddr(ips...),
		vrrp.WithGossip(gossipPort, addrs...),
	)
	if err != nil {
		log.Fatal(err)
	}
	var hctx context.Context
	var hcancel func()
	handle := func(t vrrp.Transition) {
		switch t {
		case vrrp.Backup2Master:
			log.Info("init to master")
			hctx, hcancel = context.WithCancel(context.Background())
			go run(hctx)
		case vrrp.Master2Init:
			log.Info("master to init")
			hcancel()
		case vrrp.Master2Backup:
			log.Info("master to backup")
			hcancel()
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
			if hcancel != nil {
				hcancel()
			}
			log.Warnf("received: %v", s)
			log.Warn("exiting...")
			vr.Stop()
			os.Exit(1)
		}
	}

}

func run(ctx context.Context) {
	errs := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		logrus.Infof(r.RemoteAddr)
		w.Write([]byte("ok\n"))
	})
	srv := http.Server{
		Addr:    ":8888",
		Handler: mux,
	}
	go func() {
		errs <- srv.ListenAndServe()
	}()
	for {
		select {
		case err := <-errs:
			logrus.WithError(err).Error("web server stopped")
		case <-ctx.Done():
			logrus.Warn(ctx.Err())
			srv.Shutdown(context.Background())
			return
		}
	}
}
