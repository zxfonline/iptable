package main

import (
	"fmt"

	"github.com/zxfonline/iptable"
)

func main() {
	filter := make(map[string]bool)
	filter["192.168.1.1"] = false
	filter["192.168.1.153"] = false
	filter["192.168.2.1"] = true
	filter["192.168.2.153"] = false
	filter["192.168.1.*"] = true
	filter["192.168.*.153"] = true
	filter["192.168.2.*"] = true
	filter["192.168.3.*"] = false
	//	filter["192.168.*.*"] = true
	iptable.AddIPs(filter)
	fmt.Println("---------")
	ipstr := "192.168.1.1"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.1.2"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.1.153"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.2.1"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.2.153"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.3.1"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.3.153"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.4.153"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	ipstr = "192.168.4.1"
	fmt.Println(ipstr, iptable.IsTrustedIP(ipstr))
	fmt.Println("----black-----")
	fmt.Println(iptable.GetBlackList())
	fmt.Println("----white-----")
	fmt.Println(iptable.GetWhiteList())
}
