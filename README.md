# vrrp-go
由golang实现的[VRRP-v3](https://tools.ietf.org/html/rfc5798), 点击超链接获取关于VRRP的信息。

[VRRP-v3](https://tools.ietf.org/html/rfc5798) implemented by golang，click hyperlink get details about VRRP

## Platforms support

Only linux is currently supported and tested.

## Dependencies

In order to forward virtual IP traffic to local IP, **iptables** binary is required.

## Example
```go
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
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
	preemt   bool
)

func init() {
	flag.IntVar(&vrid, "vrid", 233, "virtual router id")
	flag.IntVar(&priority, "pri", 100, "router priority")
	flag.StringVar(&iface, "iface", "eth0", "network interface")
	flag.BoolVar(&preemt, "preempt", false, "set preempt mode")
}

func main() {
	vips := []string{"172.17.0.42", "172.17.0.43"}
	log := logrus.StandardLogger()
	flag.Parse()
	vrrp.SetLogLevel(logrus.InfoLevel)
	var ips []net.IP
	for _, v := range vips {
		ips = append(ips, net.ParseIP(v))
	}
	vr, err := vrrp.NewVirtualRouter(
		vrrp.WithVRID(byte(vrid)),
		vrrp.WithInterface(iface),
		vrrp.WithAdvInterval(100*time.Millisecond),
		vrrp.WithPriority(byte(priority)),
		vrrp.WithMasterAdvInterval(100*time.Millisecond),
		vrrp.WithPreemtpMode(preemt),
		vrrp.WithIPvXAddr(ips...),
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
		w.Write([]byte("ok"))
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

```

```shell
GOOS=linux go build -o vr example/main.go
#execute on host1
./vr -vrid=200 -pri=150
#execute on host2
./vr -vrid=200 -pri=230
```

