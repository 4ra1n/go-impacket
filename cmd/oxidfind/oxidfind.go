package main

import (
	"flag"
	"fmt"
	"github.com/4ra1n/go-impacket/pkg"
	"github.com/4ra1n/go-impacket/pkg/common"
	DCERPCv5 "github.com/4ra1n/go-impacket/pkg/dcerpc/v5"
	"github.com/4ra1n/go-impacket/pkg/util"
	"log"
	"os"
	"sync"
)

var (
	ip     string
	thread int
	debug  bool
)

func init() {
	flag.StringVar(&ip, "ip", "172.20.10.*", "目标ip或ip段")
	flag.IntVar(&thread, "t", 2000, "线程数量")
	flag.BoolVar(&debug, "debug", false, "开启调试信息")
	flag.Parse()
	fmt.Println(pkg.BANNER)
	if flag.NFlag() < 1 {
		log.Fatalln("Usage: oxidfind -ip 172.20.10.*")
	}
}

func main() {
	ips, err := util.IpParse(ip)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	var wg sync.WaitGroup
	c := make(chan struct{}, thread)
	for _, i := range ips {
		options := common.ClientOptions{
			Host: i,
			Port: 135,
		}
		wg.Add(1)
		go func(ip string) {
			c <- struct{}{}
			defer wg.Done()
			session, err := DCERPCv5.NewTCPSession(options, debug)
			if err != nil {
				if debug {
					log.Printf("[-] Connect failed [%s]: %s\n", ip, err)
				}
				return
			}
			rpc, _ := DCERPCv5.TCPTransport()
			rpc.Client = session.Client
			err = rpc.RpcBindIOXIDResolver(1)
			if err != nil {
				rpc.Debug("[-]", err)
				return
			}
			address, err := rpc.ServerAlive2Request(2)
			if err != nil {
				rpc.Debug("[-]", err)
				return
			}
			fmt.Printf("[*] %s is alive\n", ip)
			for _, i := range address {
				if i != "" {
					fmt.Printf("[+] NetworkAddr: %s\n", i)
				}
			}
			<-c
		}(i)
	}
	wg.Wait()
}
