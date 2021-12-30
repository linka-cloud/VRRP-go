# vrrp-go
由golang实现的[VRRP-v3](https://tools.ietf.org/html/rfc5798), 点击超链接获取关于VRRP的信息。
[VRRP-v3](https://tools.ietf.org/html/rfc5798) implemented by golang，click hyperlink get details about VRRP

## example
```go
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
	VRID     int
	Priority int
)

func init() {
	flag.IntVar(&VRID, "vrid", 233, "virtual router ID")
	flag.IntVar(&Priority, "pri", 100, "router priority")
}

func main() {
	log := logrus.StandardLogger()
	flag.Parse()
	vrrp.SetLogLevel(logrus.InfoLevel)
	vr, err := vrrp.NewVirtualRouter(byte(VRID), "eth0", false, vrrp.IPv4)
	if err != nil {
		log.Fatal(err)
	}
	if err := vr.SetAdvInterval(100 * time.Millisecond); err != nil {
		logrus.Fatal(err)
	}
	if err := vr.SetPriorityAndMasterAdvInterval(byte(Priority), time.Millisecond*100); err != nil {
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

```

```shell
GOOS=linux go build -o vr example/main.go
#execute on host1
./vr -vrid=200 -pri=150
#execute on host2
./vr -vrid=200 -pri=230
```

