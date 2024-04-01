package main

import (
	"fmt"

	"github.com/4ra1n/go-impacket/pkg/common"
	"github.com/4ra1n/go-impacket/pkg/smb/smbv1"
)

func main() {
	port := 445
	options := common.ClientOptions{
		Host:        "192.168.197.158",
		Port:        port,
		Domain:      "",
		Workstation: "",
		Hash:        "",
		User:        "administrator",
		Password:    "administrator",
	}
	session, err := smbv1.NewSession(options, true)
	if err != nil {
		panic(err)
	}
	fmt.Println(session)
}
