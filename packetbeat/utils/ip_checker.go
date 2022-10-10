// Copyright 2019 BlueCat Networks (USA) Inc. and its affiliates
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"net"

)


func CheckIPInRange(IP string, ipNet *net.IPNet) bool {
	return ipNet.Contains(net.ParseIP(IP))
}

func CheckIPInRanges(IP string, ipNets []*net.IPNet, ips []string) bool {
	if len(ipNets) == 0 && len(ips) == 0 {
		return true
	}
	for _, ipNet := range ipNets {
		if CheckIPInRange(IP, ipNet) {
			return true
		}
	}
	for _, ip := range ips {
		if ip == IP {
			return true
		}
	}
	return false
}

func CheckIpRangeFromString(IP string, ipRange string) bool {
	_, ipNet, _ := net.ParseCIDR(ipRange)
	return CheckIPInRange(IP, ipNet)
}

// Check if the IP Address is the local IP Address
func IsLocalIP(ip string) bool {
	localAddrs, _ := GetAllLocalIP()
	for _, addr := range localAddrs {
		if addr == ip {
			return true
		}
	}
	return false
}

// Check if both of source and destination IP Address are the local IP Address
func IsInternalCall(srcIp string, dstIp string) bool {
	return IsLocalIP(srcIp) && IsLocalIP(dstIp)
}

// Get all local ip
func GetAllLocalIP() (addr []string, err error) {
    ifaces, err := net.Interfaces()
    if err != nil {
        return
    }
    var result []string
    for _, i := range ifaces {
        addrs, err := i.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            result = append(result, ip.String())
        }
    }
    return result, nil
}
