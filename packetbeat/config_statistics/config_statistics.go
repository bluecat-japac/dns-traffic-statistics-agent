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

package config_statistics

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/logp"
)

type ConfigStatistics struct {
	StatisticsDestination        string        `json:"statistics_destination"`
	StatisticsInterval           time.Duration `json:"statistics_interval"`
	MaximumClients               int           `json:"maximum_clients"`
	UrlAnnouncementDeployFromBam string        `json:"url_announcement_bam_deploy"`
	IntervalClearOutStatisCache  int           `json:"interval_clear_outstatis_cache"`
}

var (
	ConfigStat              = ConfigStatistics{IntervalClearOutStatisCache: 180, StatisticsInterval: 60}
	NAMED_CONFIG_PATH       = `/replicated/jail/named/etc/named.conf`
	REGEX_PURE_IPV4         = `((\d){1,3}\.){3}(\d){1,3}$`
	REGEX_PURE_IPV4_RANGE   = `((\d){1,3}\.){3}(\d){1,3}\/(\d){1,3}$`
	REGEX_PURE_IP_V6        = `(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::))))$`
	REGEX_PURE_IP_V6_RANGE  = `\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?\s*/[0-9]{1,3}$`
	REGEX_VIEW              = `^view.+\".+\"`
	FORMAT_ACL_CLIENTS      = "acl _TrafficStatisticsAgent_Clients"
	FORMAT_ACL_SERVERS      = "acl _TrafficStatisticsAgent_Servers"
	FORMAT_PURE_ACL_CLIENTS = "_TrafficStatisticsAgent_Clients"
	FORMAT_MATCH_CLIENTS    = "match-clients"
	ANY                     = "any"
	PREFIX_ACL              = "acl"
	REGEX_ACL_NAME          = `^acl .+ {`
	regView, _              = regexp.Compile(REGEX_VIEW)
	RegPureIpv4, _          = regexp.Compile(REGEX_PURE_IPV4)
	RegPureIpv4Range, _     = regexp.Compile(REGEX_PURE_IPV4_RANGE)
	RegPureIpv6, _          = regexp.Compile(REGEX_PURE_IP_V6)
	RegPureIpv6Range, _     = regexp.Compile(REGEX_PURE_IP_V6_RANGE)
	RegAclName, _           = regexp.Compile(REGEX_ACL_NAME)
	ACLMap                  = make(map[string][]string, 0)
)

func Init() {
	baseDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	statisticsConfigPath := filepath.Join(baseDir, "statistics_config.json")
	ConfigStat = LoadConfiguration(statisticsConfigPath)
}

func LoadConfiguration(file string) ConfigStatistics {
	var config ConfigStatistics
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		panic(err)
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}

func ReadACLInNamedConfig() ([]*net.IPNet, []*net.IPNet, []string, []string, map[int]map[string][]string) {
	logp.Info("Reading named.config at path %s", NAMED_CONFIG_PATH)
	CollectMapACL()
	IPServerRangesInACL := make([]*net.IPNet, 0)
	IPClientRangesInACL := make([]*net.IPNet, 0)
	IPsClientInACL := make([]string, 0)
	IPsServerInACL := make([]string, 0)
	MapViewIPs := make(map[int]map[string][]string, 0)
	IndexLastViewMap := make(map[string][]string, 0)
	lastView := ""
	viewIndex := -1
	file, err := os.Open(NAMED_CONFIG_PATH)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			//Find view field a line of named.conf file
			if viewName := readViewName(line); viewName != "" {
				lastView = viewName
				viewIndex += 1
				IndexLastViewMap = make(map[string][]string, 0)
			}

			switch {
			case strings.Contains(line, FORMAT_MATCH_CLIENTS):
				arrayIPsString := getArrayStringFromLineRecursive(line)
				logp.Info("Ip Array %v", arrayIPsString)
				for _, value := range arrayIPsString {
					trimedValue := strings.TrimSpace(value)
					//Normal case
					if trimedValue == ANY ||
						RegPureIpv4.MatchString(trimedValue) ||
						RegPureIpv4Range.MatchString(trimedValue) ||
						RegPureIpv6.MatchString(trimedValue) ||
						RegPureIpv6Range.MatchString(trimedValue) {
						IndexLastViewMap[lastView] = append(IndexLastViewMap[lastView], strings.ToLower(trimedValue))
					}
				}
				MapViewIPs[viewIndex] = IndexLastViewMap
			case strings.Contains(line, FORMAT_ACL_CLIENTS):
				tmp_IPClientRangesInACL, tmp_IPsClientInACL := getIPsInLine(line)
				IPClientRangesInACL = append(IPClientRangesInACL, tmp_IPClientRangesInACL...)
				IPsClientInACL = append(IPsClientInACL, tmp_IPsClientInACL...)

			case strings.Contains(line, FORMAT_ACL_SERVERS):
				tmp_IPServerRangesInACL, tmp_IPsServerInACL := getIPsInLine(line)
				IPServerRangesInACL = append(IPServerRangesInACL, tmp_IPServerRangesInACL...)
				IPsServerInACL = append(IPsServerInACL, tmp_IPsServerInACL...)
			}

		}
		if err := scanner.Err(); err != nil {
			logp.Err("Reading named.conf has an error: %v", err.Error())
			IPServerRangesInACL = make([]*net.IPNet, 0)
			IPClientRangesInACL = make([]*net.IPNet, 0)
			IPsClientInACL = make([]string, 0)
			IPsServerInACL = make([]string, 0)
		}
	} else {
		logp.Err("named.conf file doesn't exist: %v", err.Error())
	}
	return IPServerRangesInACL, IPClientRangesInACL, IPsServerInACL, IPsClientInACL, MapViewIPs
}

func CollectMapACL() {
	logp.Info("Starting collect ACL")
	ACLMap = make(map[string][]string, 0)
	file, err := os.Open(NAMED_CONFIG_PATH)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			//========================Collect acl======================================
			if aclStringMatched := RegAclName.FindString(line); aclStringMatched != "" {
				aclName := strings.Split(aclStringMatched, " ")[1]
				arrayIPsString := getArrayStringFromLine(line)
				ACLMap[aclName] = arrayIPsString
			}

		}
	} else {
		logp.Err("named.conf file doesn't exist: %v", err.Error())
	}
	logp.Info("Done collect ACL")
}

func getIPsInLine(line string) (IPRangesInACL []*net.IPNet, IPsInACL []string) {
	arrayStrIpRange, arrayStrIp, arrayStrIpV6Range, arrayStrIpV6 := matchRegexIps(line)
	for _, s := range arrayStrIpRange {
		_, ipNet, _ := net.ParseCIDR(strings.Replace(s, ";", "", -1))
		IPRangesInACL = append(IPRangesInACL, ipNet)
	}
	for _, s := range arrayStrIpV6Range {
		_, ipNet, _ := net.ParseCIDR(strings.Replace(s, ";", "", -1))
		IPRangesInACL = append(IPRangesInACL, ipNet)
	}
	for _, s := range arrayStrIp {
		IPsInACL = append(IPsInACL, strings.Replace(s, ";", "", -1))
	}
	for _, s := range arrayStrIpV6 {
		// Append IPv6 Lowcase
		IPsInACL = append(IPsInACL, strings.ToLower(strings.Replace(s, ";", "", -1)))
	}
	return
}

func getArrayStringFromLine(line string) (arrayIPsString []string) {
	ipsString := line[strings.Index(line, "{")+1 : strings.Index(line, "}")]
	arrayIPsString = strings.Split(ipsString, ";")
	return
}

func getArrayStringFromLineRecursive(line string) (arrayIpsRecursive []string) {
	ipsString := line[strings.Index(line, "{")+1 : strings.Index(line, "}")]
	arrayIPsString := strings.Split(ipsString, ";")
	arrayIpsRecursive = getIPArrayFromACLRecursive(arrayIPsString)
	return
}

func getIPArrayFromACLRecursive(arrayIPsString []string) (ipRange []string) {
	for _, ipString := range arrayIPsString {
		trimedValue := strings.TrimSpace(ipString)
		if _, exist := ACLMap[trimedValue]; exist {
			ipArrayRecur := getIPArrayFromACLRecursive(ACLMap[trimedValue])
			ipRange = append(ipRange, ipArrayRecur...)
		} else {
			ipRange = append(ipRange, trimedValue)
		}
	}
	return
}

func stringInSlice(checkString string, list []string) bool {
	for _, b := range list {
		if b == checkString {
			return true
		}
	}
	return false
}

func readViewName(line string) string {
	stringView := regView.FindAllString(line, -1)
	if len(stringView) > 0 {
		arrayString := strings.Split(stringView[0], " ")
		return strings.Replace(arrayString[len(arrayString)-1], "\"", "", -1)
	}
	return ""
}

func matchRegexIps(line string) (arrayStrIpRange []string, arrayStrIp []string, arrayStrIpV6Range []string, arrayStrIpV6 []string) {
	arrayIpsRecursive := getArrayStringFromLineRecursive(line)
	for _, ipString := range arrayIpsRecursive {
		trimedValue := strings.TrimSpace(ipString)
		if RegPureIpv4.MatchString(trimedValue) {
			arrayStrIp = append(arrayStrIp, trimedValue)
		} else if RegPureIpv6.MatchString(trimedValue) {
			arrayStrIpV6 = append(arrayStrIpV6, trimedValue)
		} else if RegPureIpv4Range.MatchString(trimedValue) {
			arrayStrIpRange = append(arrayStrIpRange, trimedValue)
		} else if RegPureIpv6Range.MatchString(trimedValue) {
			arrayStrIpV6Range = append(arrayStrIpV6Range, trimedValue)
		}
	}
	return
}


