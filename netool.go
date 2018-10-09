// Copyright 2016 zxfonline@sina.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package iptable

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/zxfonline/proxyutil"

	"github.com/zxfonline/config"
	"github.com/zxfonline/golog"
)

var (
	//ip黑白名单表
	_TrustFilterMap map[string]bool
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
	//ip过滤表
	_TrustFilterMap = make(map[string]bool)
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
				panic(fmt.Errorf("IP TABLE 节点解析错误:section=%s,option=%s,error=%v", section, option, err))
			}
			trustmap[option] = on
		}
		golog.Infof("LOAD IP TABLE FILTER:\n%+v", trustmap)
		//替换存在的
		_TrustFilterMap = trustmap
		_configurl = configurl
	} else {
		golog.Errorf("LOAD IP TABLE FILTER ERROR:%v", err)
	}
}

// 获取本地内网地址
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

// 获取本地外网地址
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

//GetExistExternalIp 获取外网iP
func GetExistExternalIp() string {
	return InterExternalIp.String()
}

//是否在黑名单中
func IsBlackIp(ipStr string) bool {
	lock.RLock()
	defer lock.RUnlock()
	if on, exist := _TrustFilterMap[ipStr]; exist {
		return !on
	}
	return false
}

//是否在白名单中
func IsWhiteIp(ipStr string) bool {
	lock.RLock()
	defer lock.RUnlock()
	if on, exist := _TrustFilterMap[ipStr]; exist {
		return on
	}
	return false
}

//获取所有的白名单
func GetWhiteList() []string {
	lock.RLock()
	defer lock.RUnlock()
	mp := _TrustFilterMap
	whitelist := make([]string, 0, len(mp))
	for ip, on := range mp {
		if on {
			whitelist = append(whitelist, ip)
		}
	}
	return whitelist
}

//获取所有的黑名单
func GetBlackList() []string {
	lock.RLock()
	defer lock.RUnlock()
	mp := _TrustFilterMap
	blacklist := make([]string, 0, len(mp))
	for ip, on := range mp {
		if !on {
			blacklist = append(blacklist, ip)
		}
	}
	return blacklist
}

//添加ip过滤 on=true 表示白名单，off表示黑名单
func AddIP(ipStr string, on bool) {
	lock.Lock()
	_TrustFilterMap[ipStr] = on
	lock.Unlock()
}

//添加ip过滤 on=true 表示白名单，off表示黑名单
func AddIPs(ips map[string]bool) {
	lock.Lock()
	for ip, on := range ips {
		if len(ip) == 0 {
			continue
		}
		_TrustFilterMap[ip] = on
	}
	lock.Unlock()
}

//删除ip名单
func DeleteIPs(ips []string) {
	lock.Lock()
	for _, ip := range ips {
		if len(ip) == 0 {
			continue
		}
		delete(_TrustFilterMap, ip)
	}
	lock.Unlock()
}

//检查ip是否是可以信任
func IsTrustedIP(ipStr string) bool {
	lock.RLock()
	if on, exist := _TrustFilterMap[ipStr]; exist {
		lock.RUnlock()
		return on
	}
	lock.RUnlock()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// 本机地址
	if ip.IsLoopback() {
		return true
	}
	// 内网地址
	mask := ip.Mask(InterMask)
	return mask.Equal(InterIPNet) || mask.Equal(InterExternalIp)
}

//检查ip是否是可以信任
func IsTrustedIP1(ipStr string) bool {
	if !CHECK_IPTRUSTED {
		return true
	}
	return IsTrustedIP(ipStr)
}

//获取连接的远程ip信息
func GetRemoteIP(con net.Conn) net.IP {
	addr := con.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

//获取连接的的ip地址(eg:192.168.1.2:1234 -->192.168.1.2)
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
