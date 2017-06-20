// Copyright 2016 zxfonline@sina.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package iptable

import (
	"errors"
	"fmt"
	"io/ioutil"
	. "net"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"

	"github.com/zxfonline/config"
	"github.com/zxfonline/golog"
)

var (
	//ip黑白名单表
	TrustFilterMap map[string]bool
	//子网掩码 默认"255, 255, 0, 0"
	InterMask IPMask = IPv4Mask(255, 255, 255, 0)
	//默认网关 默认"127, 0, 0, 0"
	InterIPNet      IP = IPv4(127, 0, 0, 0)
	InterExternalIp    = IPv4(192, 168, 0, 0)
	loadstate       int32

	//是否检测ip的安全性(不对外的http服务，可以不用检测)
	CHECK_IPTRUSTED = true
)

func init() {
	//ip过滤表
	TrustFilterMap = make(map[string]bool)
	go func() {
		defer func() {
			golog.Infof("DEFAULT LOCAL IP MASK:%s | %s", InterIPNet.String(), InterExternalIp.String())
		}()
		//初始化默认网关
		ipStr := GetLocalInternalIp()
		ip := ParseIP(ipStr)
		if ip != nil {
			mask := ip.Mask(InterMask)
			InterIPNet = mask
		}
		ipStr = GetLocalExternalIp()
		ip = ParseIP(ipStr)
		if ip != nil {
			mask := ip.Mask(InterMask)
			InterExternalIp = mask
		}
	}()
}

func LoadIpTable() {
	configurl := os.Getenv("filterIpCfg")
	if configurl == "" {
		panic(errors.New(`没找到系统变量:"filterIpCfg"`))
	}
	//读取初始化配置文件
	cfg, err := config.ReadDefault(configurl)
	if err != nil {
		panic(fmt.Errorf("加载IP过滤表[%s]错误,error=%v", configurl, err))
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
		TrustFilterMap = trustmap
	} else {
		golog.Warnf("LOAD IP TABLE FILTER ERROR:%v", err)
	}
	atomic.StoreInt32(&loadstate, 1)
}

//将内存中的数据存档
func SaveIpTable() {
	defer func() { recover() }()
	if atomic.LoadInt32(&loadstate) != 1 {
		return
	}
	configurl := os.Getenv("filterIpCfg")
	if configurl == "" {
		return
	}
	fm := TrustFilterMap
	cw := config.NewDefault()
	section := config.DEFAULT_SECTION
	for ip, state := range fm {
		if state {
			cw.AddOption(section, ip, "on")
		} else {
			cw.AddOption(section, ip, "off")
		}
	}
	cw.WriteFile(configurl, os.ModePerm, `ip过滤器名单 on=白名单(用于特殊命令使用. eg:当http服务的enable=false时白名单仍可以访问)、off=黑名单`)
}

// 获取本地内网地址。
func GetLocalInternalIp() (ip string) {
	defer func() {
		if e := recover(); e != nil {
			ip = "127.0.0.1"
		}
	}()
	addrs, err := InterfaceAddrs()
	if err != nil {
		ip = "127.0.0.1"
		return
	}

	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				return
			}
		}
	}
	ip = "127.0.0.1"
	return
}

// 获取本地外网地址。
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

//是否在黑名单中
func IsBlackIp(ipStr string) bool {
	if on, exist := TrustFilterMap[ipStr]; exist {
		return !on
	}
	return false
}

//是否在白名单中
func IsWhiteIp(ipStr string) bool {
	if on, exist := TrustFilterMap[ipStr]; exist {
		return on
	}
	return false
}

//检查ip是否是可以信任
func IsTrustedIP(ipStr string, ignore_ipfilter bool) bool {
	if !ignore_ipfilter && !CHECK_IPTRUSTED {
		return true
	}
	if on, exist := TrustFilterMap[ipStr]; exist {
		return on
	}
	ip := ParseIP(ipStr)
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

//获取连接的远程ip信息
func GetRemoteIP(con Conn) IP {
	addr := con.RemoteAddr().String()
	host, _, err := SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return ParseIP(host)
}

//获取连接的的ip地址(eg:192.168.1.2:1234 -->192.168.1.2)
func GetRemoteAddrIP(remoteAddr string) string {
	host, _, err := SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := ParseIP(host)
	if ip == nil {
		return remoteAddr
	}
	return ip.String()
}
