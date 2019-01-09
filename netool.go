// Copyright 2016 zxfonline@sina.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package iptable

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/zxfonline/proxyutil"

	"github.com/zxfonline/config"
	"github.com/zxfonline/golog"
	"github.com/zxfonline/strutil"
)

var (
	//ip黑白名单表 key=string(net.IP) value=true:white false:black
	_TrustFilterMap = make(map[string]bool)
	lock            sync.RWMutex
	//子网掩码 默认"255, 255, 255, 0"
	InterMask net.IPMask = net.IPv4Mask(255, 255, 255, 0)
	//默认网关 默认"127, 0, 0, 0"
	InterIPNet      net.IP = net.IPv4(192, 168, 1, 0)
	InterExternalIp        = net.IPv4(192, 168, 1, 0)

	//是否检测ip的安全性(不对外的http服务，可以不用检测)
	CHECK_IPTRUSTED = true
	//默认
	_configurl string = "../runtime/iptable.ini"
)

func init() {
	go func() {
		defer func() {
			golog.Infof("DEFAULT LOCAL IP MASK:%s | %s", InterIPNet.String(), InterExternalIp.String())
		}()
		//初始化默认网关
		// ipStr := GetLocalInternalIp()
		// ip := net.ParseIP(ipStr)
		// if ip != nil {
		// 	mask := ip.Mask(InterMask)
		// 	InterIPNet = mask
		// }
		ipStr := GetLocalExternalIp()
		ip := net.ParseIP(ipStr)
		if ip != nil {
			mask := ip.Mask(InterMask)
			InterExternalIp = mask
		}
	}()
	// LoadIpTable("")
}

func LoadIpTable(configurl string) {
	if len(configurl) == 0 {
		configurl = _configurl
	}
	//读取初始化配置文件
	cfg, err := config.ReadDefault(configurl)
	if err != nil {
		golog.Errorf("加载IP过滤表[%s]错误,error=%v", configurl, err)
		return
	}
	//解析系统环境变量
	section := config.DEFAULT_SECTION
	if options, err := cfg.SectionOptions(section); err == nil && options != nil {
		trustmap := make(map[string]bool)
		for _, option := range options {
			//on=true 表示白名单，off表示黑名单
			on, err := cfg.Bool(section, option)
			if err != nil {
				golog.Warnf("IP TABLE parse err,section:%s,option:%s,err:%v.", section, option, err)
			} else {
				ip := ParseFilterIp(option)
				if ip != nil {
					trustmap[string(ip)] = on
				} else {
					golog.Warnf("IP TABLE parse err,section:%s,%s=%v.", section, option, on)
				}
			}
		}
		//替换存在的
		_TrustFilterMap = trustmap
		PrintIpFilte()
		_configurl = configurl
	} else {
		golog.Errorf("LOAD IP TABLE FILTER ERROR:%v", err)
	}
}

//PrintIpFilte 打印ip过滤表
func PrintIpFilte() {
	lock.RLock()
	defer lock.RUnlock()
	bb := bytes.NewBufferString("IP TABLE FILTER:\n")
	count := 0
	var str string
	for k, v := range _TrustFilterMap {
		if count > 0 {
			bb.WriteString("\n")
		}
		str = net.IP(k).String()
		str = strings.Replace(str, "255", "*", -1)
		bb.WriteString(str)
		bb.WriteString("=")
		if v {
			bb.WriteString("white")
		} else {
			bb.WriteString("black")
		}
		count++
	}
	golog.Infoln(bb.String())
}

//ParseFilterIp 获取匹配ip模板
func ParseFilterIp(ipmatch string) net.IP {
	ipmatch = strings.TrimSpace(ipmatch)
	if len(ipmatch) == 0 {
		return nil
	}
	if !strings.Contains(ipmatch, ":") { //ipv4 otherwise ipv6
		ipmatch = strings.Replace(ipmatch, "*", "255", -1)
		ipcs := strings.Split(ipmatch, ".")
		for i, v := range ipcs {
			v = strings.TrimSpace(v)
			if len(v) == 0 {
				ipcs[i] = "255"
			} else {
				ipcs[i] = fmt.Sprintf("%d", strutil.Stoi(v, 0))
			}
		}
		if iplen := len(ipcs); iplen < 4 {
			for i := 0; i < 4-iplen; i++ {
				ipcs = append(ipcs, "255")
			}
		}
		ipmatch = strings.Join(ipcs, ".")
	}
	return net.ParseIP(ipmatch)
}

//AddIpFilter 添加ip过滤器模板
func AddIpFilter(ipmatch string, whiteIp bool) {
	ip := ParseFilterIp(ipmatch)
	if ip != nil {
		lock.Lock()
		_TrustFilterMap[string(ip)] = whiteIp
		lock.Unlock()
	} else {
		golog.Warnf("%s=%v,parse err.", ipmatch, whiteIp)
	}
}

//GetLocalInternalIp 获取本地内网地址
func GetLocalInternalIp() (ip string) {
	defer func() {
		if e := recover(); e != nil {
			ip = "127.0.0.1"
		}
	}()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		ip = "127.0.0.1"
		return
	}

	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				return
			}
		}
	}
	ip = "127.0.0.1"
	return
}

//GetLocalExternalIp 获取本地外网地址
func GetLocalExternalIp() (ip string) {
	defer func() {
		if e := recover(); e != nil {
			ip = "127.0.0.1"
		}
	}()
	resp, err := http.Get("http://myexternalip.com/raw")
	if err != nil {
		ip = "127.0.0.1"
		return
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		ip = "127.0.0.1"
		return
	}
	reg := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	ip = reg.FindString(string(result))
	return
}

//IsBlackIp 是否在黑名单中(只关系黑名单是否存在)
func IsBlackIp(ipStr string) bool {
	lock.RLock()
	defer lock.RUnlock()
	inip := net.ParseIP(ipStr)
	if inip == nil {
		return false
	}
	// 本机地址
	if inip.IsLoopback() {
		return false
	}
	for libip, state := range _TrustFilterMap {
		if state { //不关心白名单
			continue
		}
		outip := ipparse(inip, net.IP(libip))
		if inip.Equal(outip) { //匹配
			return true
		}
	}
	return false
}

//IsWhiteIp 是否在白名单中(没在黑名单且在白名单)
func IsWhiteIp(ipStr string) bool {
	lock.RLock()
	defer lock.RUnlock()
	inip := net.ParseIP(ipStr)
	if inip == nil {
		return false
	}
	// 本机地址
	if inip.IsLoopback() {
		return true
	}
	for libip, state := range _TrustFilterMap {
		if state { //不关心白名单
			continue
		}
		outip := ipparse(inip, net.IP(libip))
		if inip.Equal(outip) { //匹配黑名单,在黑名单中就不能是白名单，即使白名单有匹配
			return false
		}
	}

	for libip, state := range _TrustFilterMap {
		if !state {
			continue
		}
		outip := ipparse(inip, net.IP(libip))
		if inip.Equal(outip) { //匹配
			return true
		}
	}
	return false
}

//GetWhiteList 获取所有的白名单过滤器模板
func GetWhiteList() []string {
	lock.RLock()
	defer lock.RUnlock()
	mp := _TrustFilterMap
	whitelist := make([]string, 0, len(mp))
	var str string
	for ip, on := range mp {
		if on {
			str = net.IP(ip).String()
			str = strings.Replace(str, "255", "*", -1)
			whitelist = append(whitelist, str)
		}
	}
	return whitelist
}

//GetBlackList 获取所有的黑名单过滤器模板
func GetBlackList() []string {
	lock.RLock()
	defer lock.RUnlock()
	mp := _TrustFilterMap
	blacklist := make([]string, 0, len(mp))
	var str string
	for ip, on := range mp {
		if !on {
			str = net.IP(ip).String()
			str = strings.Replace(str, "255", "*", -1)
			blacklist = append(blacklist, str)
		}
	}
	return blacklist
}

//AddIP 添加ip过滤模板 on=true 表示白名单，off表示黑名单
func AddIP(ipmatch string, on bool) {
	AddIpFilter(ipmatch, on)
	PrintIpFilte()
}

//AddIPs 添加ip过滤模板 on=true 表示白名单，off表示黑名单
func AddIPs(ipmatchs map[string]bool) {
	for ipmatch, on := range ipmatchs {
		AddIpFilter(ipmatch, on)
	}
	PrintIpFilte()
}

//DeleteIPs 删除ip名单模板过滤器
func DeleteIPs(ipmatchs []string) {
	lock.Lock()
	for _, ipmatch := range ipmatchs {
		ip := ParseFilterIp(ipmatch)
		if ip != nil {
			delete(_TrustFilterMap, string(ip))
		} else {
			golog.Warnf("ip:%s,parse err.", ipmatch)
		}
	}
	lock.Unlock()
	PrintIpFilte()
}

//IsTrustedIP 检查ip是否可信任(没在黑名单且在白名单)
func IsTrustedIP(ipStr string) bool {
	lock.RLock()
	defer lock.RUnlock()
	inip := net.ParseIP(ipStr)
	if inip == nil {
		return false
	}
	// 本机地址
	if inip.IsLoopback() {
		return true
	}
	for libip, state := range _TrustFilterMap {
		if state { //不关心白名单
			continue
		}
		outip := ipparse(inip, net.IP(libip))
		if inip.Equal(outip) { //匹配黑名单,在黑名单中就不能是白名单，即使白名单有匹配
			return false
		}
	}
	for libip, state := range _TrustFilterMap {
		if !state {
			continue
		}
		outip := ipparse(inip, net.IP(libip))
		if inip.Equal(outip) { //匹配
			return true
		}
	}
	// 内网地址
	mask := inip.Mask(InterMask)
	return mask.Equal(InterIPNet) || mask.Equal(InterExternalIp)
}

func ipparse(ip, base net.IP) net.IP {
	n := len(ip)
	if n != len(base) {
		return nil
	}
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		if base[i] == 255 { //all
			out[i] = ip[i]
		} else {
			out[i] = base[i]
		}
	}
	return out
}

//IsTrustedIP1 检查ip是否可信任
func IsTrustedIP1(ipStr string) bool {
	if !CHECK_IPTRUSTED {
		return true
	}
	return IsTrustedIP(ipStr)
}

//GetRemoteIP 获取连接的远程ip信息
func GetRemoteIP(con net.Conn) net.IP {
	addr := con.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

//GetRemoteAddrIP 获取连接的的ip地址(eg:192.168.1.2:1234 -->192.168.1.2)
func GetRemoteAddrIP(remoteAddr string) string {
	reqIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		reqIP = remoteAddr
	}
	origIP := net.ParseIP(reqIP)
	if origIP == nil {
		return remoteAddr
	}
	return origIP.String()
}

// RequestIP returns the string form of the original requester's IP address for
// the given request, taking into account X-Forwarded-For if applicable.
// If the request was from a loopback address, then we will take the first
// non-loopback X-Forwarded-For address. This is under the assumption that
// your golang server is running behind a reverse proxy.
func RequestIP(r *http.Request) string {
	return proxyutil.RequestIP(r)
}
