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

package statsdns

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/config_statistics"
	"github.com/elastic/beats/packetbeat/model"

	"github.com/elastic/beats/packetbeat/outstats"
	"github.com/elastic/beats/packetbeat/utils"
	mkdns "github.com/miekg/dns"
)

const (
	CLIENT     = "perClient"
	AUTHSERVER = "perServer"
	VIEW       = "perView"
	NOERROR    = "NOERROR"
	NXDOMAIN   = "NXDOMAIN"
	SERVFAIL   = "SERVFAIL"
	FORMERR    = "FORMERR"
	REFUSED    = "REFUSED"
	RR_NS      = "NS"
	RQ_C_MAP   = "Incoming"
	RQ_S_MAP   = "Outgoing"
	QUERY      = "Query"
	RESPONSE   = "Response"
	RQ_ERR_MAP = "Formerr"
	NXRRSET    = "NXRRSET"
)

type (
	// Statistics service
	StatisticsService struct {
		Start    time.Time                 `json:"start"`
		End      time.Time                 `json:"end"`
		StatsMap map[string]*StatisticsDNS `json:"stats_map"`
	}

	// Statistics for a client or an AS.
	StatisticsDNS struct {
		Type       string      `json:"type"`
		DNSMetrics *DNSMetrics `json:"dnsmetrics"`
	}

	// Statistics details
	DNSMetrics struct {
		TotalQueries        int64    `json:"total_queries"`
		TotalResponses      int64    `json:"total_responses"`
		Recursive           int64    `json:"recursive"`
		SuccessfulRecursive int64    `json:"successful_recursive"`
		SuccessfulNoAuthAns int64    `json:"successful_noauthans"`
		Duplicated          int64    `json:"duplicated"`
		AverageTime         *float64 `json:"average_time"`
		Successful          int64    `json:"successful"`
		ServerFail          int64    `json:"server_fail"`
		NXDomain            int64    `json:"nx_domain"`
		FormatError         int64    `json:"format_error"`
		NXRRSet             int64    `json:"nx_rrset"`
		Referral            int64    `json:"referral"`
		Refused             int64    `json:"refused"`
		OtherRcode          int64    `json:"other_rcode"`
	}

	// Query map for recursion counting
	RequestMap struct {
		RequestMessage map[string]map[string]string
	}
)

var (
	StatSrv                      *StatisticsService
	ReqMap                       *RequestMap
	mutex                        = &sync.RWMutex{}
	StatInterval                 = time.Duration(30)
	MaximumClients               = 200
	IpNetsClient                 []*net.IPNet
	IpNetsServer                 []*net.IPNet
	IpsClient                    []string
	IpsServer                    []string
	UrlAnnouncementDeployFromBam string
	MapViewIPs                   map[int]map[string][]string
)

func InitStatisticsDNS() {
	GetConfigDNSStatistics()
	go func() {
		ticker := time.NewTicker(StatInterval * time.Second)
		StatSrv = &StatisticsService{Start: time.Now(), StatsMap: make(map[string]*StatisticsDNS, MaximumClients)}
		ReqMap = &RequestMap{RequestMessage: make(map[string]map[string]string, MaximumClients)}
		//===================Create Counter For PerView============================
		//go func() {
		//	CreateCounterMetricPerView(MapViewIPs)
		//}()
		//===================End Create Counter For PerView========================
		for {
			//===================Create Counter For PerView==========================
			go func() {
				CreateCounterMetricPerView(MapViewIPs)
			}()
			//===================End Create Counter For PerView======================
			t := <-ticker.C
			mutex.Lock()
			logp.Info("Starting %s", t)
			StatSrv.End = t
			b, err := json.Marshal(StatSrv)
			if err != nil {
				logp.Error(err)
				continue
			}
			logp.Info("DNS_Statistics: %s", b)
			// open new thread to call the API
			go func() {
				outstats.PublishToSNMPAgent(string(b))
			}()
			StatSrv = &StatisticsService{Start: t, StatsMap: make(map[string]*StatisticsDNS, MaximumClients)}
			ReqMap = &RequestMap{RequestMessage: make(map[string]map[string]string, MaximumClients)}
			mutex.Unlock()
		}
	}()
}

func IsValidInACL(statIP string, metricType string) bool{
	switch metricType {
	case CLIENT:
		if !utils.CheckIPInRanges(statIP, IpNetsClient, IpsClient) {
			return false
		}
	case AUTHSERVER:
		if !utils.CheckIPInRanges(statIP, IpNetsServer, IpsServer) {
			return false
		}
	}
	return true
}

//Create statistics for perClient, perServer and perView. Note metricType="perView" => (key of map statistic clientIP = key viewName)
func newStats(clientIp string, metricType string) bool {
	// Don't want to be calculating the internal messages or ip that doesn't in range in config statistics_config.json
	if !IsValidInACL(clientIp, metricType) {
		return false
	}
	if _, exist := StatSrv.StatsMap[clientIp]; !exist {
		averagetime := float64(0)
		stats := &StatisticsDNS{
			Type: metricType,
			DNSMetrics: &DNSMetrics{
				AverageTime: &averagetime,
			},
		}
		StatSrv.StatsMap[clientIp] = stats
	}
	return true
}

func ReceivedMessage(msg *model.Record) {
	mutex.Lock()
	defer mutex.Unlock()
	// Don't want to be calculating the internal messages
	if utils.IsInternalCall(msg.Src.IP, msg.Dst.IP) {
		return
	}
	metricType := CLIENT
	clientIP := msg.Src.IP
	if utils.IsLocalIP(clientIP) {
		metricType = AUTHSERVER
		clientIP = msg.Dst.IP
	}

	answersCount := msg.DNS.AnswersCount
	responseTime := msg.ResponseTime
	responseCode := msg.DNS.ResponseCode
	authoritiesCount := msg.DNS.AuthoritiesCount

	// First message for this client/AS
	if !newStats(clientIP, metricType) {
		return
	}

	if responseCode == NOERROR {
		if answersCount > 0 {
			// Successful case
			IncrDNSStatsSuccessful(clientIP)
			IncrDNSStatsSuccessfulForPerView(clientIP, metricType)
			if !msg.DNS.Flags.Authoritative {
				IncrDNSStatsSuccessfulNoAuthAns(clientIP)
				IncrDNSStatsSuccessfulNoAuthAnsForPerView(clientIP)
			}
		} else {
			// Referral: NOERROR, no answer and NS records in Authority
			var foundNS = false
			if authoritiesCount > 0 {
				for _, author := range msg.DNS.Authorities {
					foundNS = author.Type == RR_NS
					if foundNS {
						break
					}
				}
			}

			if foundNS {
				IncrDNSStatsReferral(clientIP)
				IncrDNSStatsReferralForPerView(clientIP, metricType)
			}
		}
	} else if responseCode == NXRRSET {
		// RRCode == 8 and answersCount == 0
		IncrDNSStatsNXRRSet(clientIP)
		IncrDNSStatsNXRRSetForPerView(clientIP, metricType)
	} else if responseCode == NXDOMAIN {
		IncrDNSStatsNXDomain(clientIP)
		IncrDNSStatsNXDomainForPerView(clientIP, metricType)
	} else if responseCode == SERVFAIL {
		IncrDNSStatsServerFail(clientIP)
		IncrDNSStatsServerFailForPerView(clientIP, metricType)
	} else if responseCode == REFUSED {
		IncrDNSStatsRefused(clientIP)
		IncrDNSStatsRefusedForPerView(clientIP, metricType)
	} else if responseCode == FORMERR {
		// Should not be run into here
		// We already handled when parsing the packets
		IncrDNSStatsFormatError(clientIP)
		IncrDNSStatsFormatErrorForPerView(clientIP, metricType)

	} else {
		IncrDNSStatsOtherRCode(clientIP)
		IncrDNSStatsOtherRCodeForPerView(clientIP, metricType)
	}

	CalculateAverageTime(clientIP, responseTime)
	CalculateAverageTimePerView(clientIP, responseTime, metricType)
}

func CheckMetricType(srcIp string, dstIp string) (statIP string, metricType string){
	if utils.IsLocalIP(dstIp) {
		statIP = srcIp
		metricType = CLIENT
	} else {
		statIP = dstIp
		metricType = AUTHSERVER
	}
	return
}

//Create metric for the Client/AS/Forwarder
func CreateCounterMetric(srcIp string, dstIp string) {
	// if utils.IsInternalCall(srcIp, dstIp) {
	// 	return
	// }
	statIP, metricType := CheckMetricType(srcIp, dstIp)
	newStats(statIP, metricType)
}

//Create metric for perView
func CreateCounterMetricPerView(mapViewIPs map[int]map[string][]string) {
	for i := 0; i < len(mapViewIPs); i++ {
		for viewName, _ := range mapViewIPs[i] {
			status := newStats(viewName, VIEW)
			if !status {
				logp.Err("Couldn't Create View : %s", viewName)
			}
		}
	}

}

func Queries(srcIp string, dstIp string) {
	if !utils.IsLocalIP(srcIp) {
		if _, exist := StatSrv.StatsMap[srcIp]; exist {
			IncrDNSStatsTotalQueries(srcIp)
		} else {
			go func() {
				delayTicker := time.NewTicker(1 * time.Second)
				<- delayTicker.C
				status := newStats(srcIp, CLIENT)
				if status == false {
					return
				}
				IncrDNSStatsTotalQueries(srcIp)
			}()
		}
	} else {
		if _, exist := StatSrv.StatsMap[dstIp]; exist {
			IncrDNSStatsTotalQueries(dstIp)
		} else {
			go func(){
				delayTicker := time.NewTicker(1 * time.Second)
				<- delayTicker.C
				status := newStats(dstIp, AUTHSERVER)
				if status == false{
					return
				}
				IncrDNSStatsTotalQueries(dstIp)
			}()
		}
	}
}

func QueriesForPerView(srcIp string) {
	if !utils.IsLocalIP(srcIp) {
		if viewName := FindClientInView(srcIp); viewName != "" {
			IncrDNSStatsTotalQueries(viewName)
		}
	}
}

func Response(srcIp string, dstIp string) {
	if !utils.IsLocalIP(dstIp) {
		if _, exist := StatSrv.StatsMap[dstIp]; exist {
			IncrDNSStatsTotalResponses(dstIp)
		} else {
			go func(){
				delayTicker := time.NewTicker(1 * time.Second)
				<- delayTicker.C
				status := newStats(dstIp, CLIENT)
				if status == false{
					return
				}
				IncrDNSStatsTotalResponses(dstIp)
			}()
		}
	} else {
		if _, exist := StatSrv.StatsMap[srcIp]; exist {
			IncrDNSStatsTotalResponses(srcIp)
		} else {
			go func() {
				delayTicker := time.NewTicker(1 * time.Second)
				<- delayTicker.C
				status := newStats(srcIp, AUTHSERVER)
				if status == false {
					return
				}
				IncrDNSStatsTotalResponses(srcIp)
			}()
		}
	}
}

func ResponseForPerView(dstIp string) {
	if !utils.IsLocalIP(dstIp) {
		if viewName := FindClientInView(dstIp); viewName != "" {
			IncrDNSStatsTotalResponses(viewName)
		}
	}
}

func IncreaseQueryCounter(srcIp string, dstIp string, mode string) {
	// if utils.IsInternalCall(srcIp, dstIp) {
	// 	return
	// }
	switch mode {
	case QUERY:
		Queries(srcIp, dstIp)
		break
	case RESPONSE:
		Response(srcIp, dstIp)
		break
	}
}

func IncreaseQueryCounterForPerView(srcIp string, dstIp string, mode string) {
	// if utils.IsInternalCall(srcIp, dstIp) {
	// 	return
	// }
	switch mode {
	case QUERY:
		QueriesForPerView(srcIp)
		break
	case RESPONSE:
		ResponseForPerView(dstIp)
		break
	}
}

func IncrDNSStatsTotalQueries(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.TotalQueries, 1)
}

func IncrDNSStatsTotalQueriesForPerView(clientIp string) {
	if viewName := FindClientInView(clientIp); viewName != "" {
		atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.TotalQueries, 1)
	}
}

func IncrDNSStatsTotalResponses(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.TotalResponses, 1)
}

func IncrDNSStatsRecursive(clientIp string) {
	if !newStats(clientIp, CLIENT) {
		return
	}
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.Recursive, 1)
}

func IncrDNSStatsRecursiveForPerClient(clientIp string) {
	if viewName := FindClientInView(clientIp); viewName != "" {
		atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.Recursive, 1)
	}
}

func IncrDNSStatsDuplicated(clientIp string) {
	if !utils.IsLocalIP(clientIp) && newStats(clientIp, CLIENT) {
		atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.Duplicated, 1)
	}
}

func IncrDNSStatsDuplicatedForPerView(clientIp string) {
	if !utils.IsLocalIP(clientIp) {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.Duplicated, 1)
		}
	}
}

func IncrDNSStatsSuccessful(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.Successful, 1)
}

func IncrDNSStatsSuccessfulForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.Successful, 1)
		}
	}
}

func IncrDNSStatsSuccessfulNoAuthAns(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.SuccessfulNoAuthAns, 1)
}

func IncrDNSStatsSuccessfulNoAuthAnsForPerView(clientIp string) {
	if viewName := FindClientInView(clientIp); viewName != "" {
		atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.SuccessfulNoAuthAns, 1)
	}
}

func IncrDNSStatsSuccessfulRecursive(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.SuccessfulRecursive, 1)
}

func IncrDNSStatsSuccessfulRecursiveForPerView(clientIp string) {
	if viewName := FindClientInView(clientIp); viewName != "" {
		atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.SuccessfulRecursive, 1)
	}
}

func IncrDNSStatsServerFail(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.ServerFail, 1)
}

func IncrDNSStatsServerFailForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.ServerFail, 1)
		}
	}
}

func IncrDNSStatsNXDomain(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.NXDomain, 1)
}

func IncrDNSStatsNXDomainForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.NXDomain, 1)
		}
	}
}

func IncrDNSStatsFormatError(clientIp string) {
	if !utils.IsLocalIP(clientIp) && newStats(clientIp, CLIENT) {
		atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.FormatError, 1)
	}
}

func IncrDNSStatsFormatErrorForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			if !utils.IsLocalIP(clientIp) && newStats(viewName, VIEW) {
				atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.FormatError, 1)
			}
		}
	}
}

func IncrDNSStatsNXRRSet(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.NXRRSet, 1)
}

func IncrDNSStatsNXRRSetForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.NXRRSet, 1)
		}
	}
}

func IncrDNSStatsReferral(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.Referral, 1)
}

func IncrDNSStatsReferralForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.Referral, 1)
		}
	}
}

func IncrDNSStatsRefused(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.Refused, 1)
}

func IncrDNSStatsRefusedForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.Refused, 1)
		}
	}

}

func IncrDNSStatsOtherRCode(clientIp string) {
	atomic.AddInt64(&StatSrv.StatsMap[clientIp].DNSMetrics.OtherRcode, 1)
}

func IncrDNSStatsOtherRCodeForPerView(clientIp string, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			atomic.AddInt64(&StatSrv.StatsMap[viewName].DNSMetrics.OtherRcode, 1)
		}
	}
}

func CalculateAverageTime(clientIp string, responseTime float64) {
	statisticsDNS, ok := StatSrv.StatsMap[clientIp]
	if !ok {
		return
	}
	averageTime := *statisticsDNS.DNSMetrics.AverageTime
	toTalMessage := statisticsDNS.DNSMetrics.TotalQueries
	if statisticsDNS.Type == AUTHSERVER {
		toTalMessage = statisticsDNS.DNSMetrics.TotalResponses
	}
	if toTalMessage == 0 {
		toTalMessage = 1
	}
	*statisticsDNS.DNSMetrics.AverageTime = (averageTime*float64(toTalMessage-1) + responseTime) / float64(toTalMessage)
}

func CalculateAverageTimePerView(clientIp string, responseTime float64, metricType string) {
	if metricType == CLIENT {
		if viewName := FindClientInView(clientIp); viewName != "" {
			statisticsDNS, ok := StatSrv.StatsMap[viewName]
			if !ok {
				return
			}
			averageTime := *statisticsDNS.DNSMetrics.AverageTime
			toTalMessage := statisticsDNS.DNSMetrics.TotalQueries
			if toTalMessage == 0 {
				toTalMessage = 1
			}
			*statisticsDNS.DNSMetrics.AverageTime = (averageTime*float64(toTalMessage-1) + responseTime) / float64(toTalMessage)
		}
	}
}

func FindClientInView(clientIP string) string {
	result := ""
	foundView := false
	for i := 0; i < len(MapViewIPs); i++ {
		for viewName := range MapViewIPs[i] {
			for _, matchIP := range MapViewIPs[i][viewName] {
				//Ingore case
				if strings.Contains(matchIP, "!") {
					//Ignore Case Ignore for IPv4 Range
					if ipv4RangeString := config_statistics.RegPureIpv4Range.FindString(matchIP); ipv4RangeString != "" {
						//Normal Ipv4 Range Case
						if utils.CheckIpRangeFromString(clientIP, ipv4RangeString) {
							result = ""
							foundView = true
							break
						}
					}
					//Ignore Case for IPv6 Range
					if ipv6RangeString := config_statistics.RegPureIpv4Range.FindString(matchIP); ipv6RangeString != "" {
						//Normal Ipv6 Range Case
						if utils.CheckIpRangeFromString(clientIP, ipv6RangeString) {
							result = ""
							foundView = true
							break
						}
					}
					//Case for Ignore IP
					if strings.Contains(matchIP, clientIP) {
						result = ""
						foundView = true
						break
					}
				} else {
					//Allow case
					//Allow Case for IPv4 Range
					if ipv4RangeString := config_statistics.RegPureIpv4Range.FindString(matchIP); ipv4RangeString != "" {
						//Normal Ipv4 Range Case
						if utils.CheckIpRangeFromString(clientIP, ipv4RangeString) {
							result = viewName
							foundView = true
							break
						}
					}
					//Allow Case for IPv6 Range
					if ipv6RangeString := config_statistics.RegPureIpv4Range.FindString(matchIP); ipv6RangeString != "" {
						//Normal Ipv6 Range Case
						if utils.CheckIpRangeFromString(clientIP, ipv6RangeString) {
							result = viewName
							foundView = true
							break
						}
					}
					//Matching IP case
					if matchIP == clientIP || matchIP == "any" {
						result = viewName
						foundView = true
						break
					}
				}
			}
			if foundView {
				break
			}
		}
		if foundView && result != "" {
			break
		}
	}
	return result
}

func GetConfigDNSStatistics() {
	logp.Info("GetConfigDNSStatistics")
	//Init and read config dns statistic
	config_statistics.Init()
	StatInterval = config_statistics.ConfigStat.StatisticsInterval
	MaximumClients = config_statistics.ConfigStat.MaximumClients
	UrlAnnouncementDeployFromBam = strings.Replace(config_statistics.ConfigStat.UrlAnnouncementDeployFromBam, "http://", "", -1)
	//Read named.conf get ACL Ips Range
	logp.Info("Reading ACL In Named Config")
	IPServerRangesInACL, IPClientRangesInACL, IPsServerInACL, IPsClientInACL, MapViewIPsInMatchClients := config_statistics.ReadACLInNamedConfig()

	IpNetsServer = IPServerRangesInACL
	IpNetsClient = IPClientRangesInACL
	IpsServer = IPsServerInACL
	IpsClient = IPsClientInACL
	MapViewIPs = MapViewIPsInMatchClients

	logp.Info("IPs Range In ACL Server: %v", IpNetsServer)
	logp.Info("IPs Range In ACL Client: %v", IpNetsClient)
	logp.Info("IP In ACL Server: %v", IpsServer)
	logp.Info("IPs In ACL Client: %v", IpsClient)
	logp.Info("Map View Client IPs %v", MapViewIPs)
}

func ReceiveHttpRequest(payloadString string) {
	arraySplitUrlAnnouncementFromBam := strings.Split(UrlAnnouncementDeployFromBam, "/")
	checkUri := strings.Contains(payloadString, arraySplitUrlAnnouncementFromBam[len(arraySplitUrlAnnouncementFromBam)-1])
	checkHostPort := strings.Contains(payloadString, arraySplitUrlAnnouncementFromBam[0])
	if checkUri && checkHostPort {
		logp.Info("http request with payload %s", payloadString)
		GetConfigDNSStatistics()
	}
}

// Store all request messages into the corresponding map for Incoming messages and Outgoing messages
func AddRequestMsgMap(clientIP, srvIP string, reqID uint16, questions []mkdns.Question) {
	mutex.Lock()
	defer mutex.Unlock()
	if len(questions) > 0 && !utils.IsInternalCall(clientIP, srvIP) {
		for _, question := range questions {
			var rqItem string
			var metricType string
			rqKey := genKeyItem(question)
			if !utils.IsLocalIP(clientIP) {
				metricType = RQ_C_MAP
				rqItem = genValueItem(reqID, clientIP, question)
			} else {
				metricType = RQ_S_MAP
				// Outgoing map use the same key and value
				rqItem = rqKey
			}
			if _, exist := ReqMap.RequestMessage[metricType]; !exist {
				ReqMap.RequestMessage[metricType] = make(map[string]string)
			}
			// Make sure only the first received query will be added into the map
			// The first received client's request will be counted as recursion in case recursion happened
			if _, exist := ReqMap.RequestMessage[metricType][rqKey]; !exist {
				ReqMap.RequestMessage[metricType][rqKey] = rqItem
			}
		}
	}
}

// Extract the client question from the response and find it from the Outgoing messages
// Then find client question from the Incoming messages
// All found the client question, increase the recursive value for the client stat, then remove out the request from the maps
func CalculateRecursiveMsg(clientIP, srvIP string, reqID uint16, questions []mkdns.Question, dnsMsg *mkdns.Msg) {
	mutex.Lock()
	defer mutex.Unlock()
	if len(questions) > 0 && !utils.IsInternalCall(clientIP, srvIP) {

		for _, question := range questions {
			rqKey := genKeyItem(question)
			if !existQuery(rqKey, rqKey, RQ_S_MAP) {
				continue
			}
			rqItem := genValueItem(reqID, clientIP, question)
			if !existQuery(rqKey, rqItem, RQ_C_MAP) || utils.IsLocalIP(clientIP) {
				continue
			}
			//If Successful Recursion
			if dnsMsg.MsgHdr.Rcode == 0 && len(dnsMsg.Answer) > 0 {
				IncrDNSStatsSuccessfulRecursive(clientIP)
				IncrDNSStatsSuccessfulRecursiveForPerView(clientIP)
			}
			IncrDNSStatsRecursive(clientIP)
			IncrDNSStatsRecursiveForPerClient(clientIP)
			delete(ReqMap.RequestMessage[RQ_S_MAP], rqKey)
			delete(ReqMap.RequestMessage[RQ_C_MAP], rqKey)
		}
	}
}

func genValueItem(reqID uint16, clientIP string, question mkdns.Question) string {
	return fmt.Sprintf("%d %s %s %d %d", reqID, clientIP, question.Name, question.Qtype, question.Qclass)
}

func genKeyItem(question mkdns.Question) string {
	return fmt.Sprintf("%s %d %d", question.Name, question.Qtype, question.Qclass)
}

func existQuery(rqKey, rqItem, metricType string) bool {
	existing := false
	if value, exist := ReqMap.RequestMessage[metricType][rqKey]; exist {
		existing = value == rqItem
	}
	return existing
}

func HandleRequestDecodeErr(clientIP, srvIP string) {
	if !utils.IsInternalCall(clientIP, srvIP) {
		if !utils.IsLocalIP(clientIP) {
			IncrDNSStatsTotalQueries(clientIP)
			IncrDNSStatsTotalQueriesForPerView(clientIP)
		}
	}
}

func HandleResponseDecodeErr(clientIP, srvIP string, RCodeString string) {
	if !utils.IsInternalCall(clientIP, srvIP) {
		if !utils.IsLocalIP(clientIP) {
			if RCodeString == FORMERR {
				IncrDNSStatsFormatError(clientIP)
				IncrDNSStatsFormatErrorForPerView(clientIP, CLIENT)
			} else {
				IncrDNSStatsOtherRCode(clientIP)
				IncrDNSStatsOtherRCodeForPerView(clientIP, CLIENT)
			}
			IncrDNSStatsTotalResponses(clientIP)
			ResponseForPerView(clientIP)
		}
	}
}

func HandleResponseTruncated(clientIP, srvIP string) {
	if !utils.IsInternalCall(clientIP, srvIP) {
		if !utils.IsLocalIP(clientIP) {
			IncrDNSStatsSuccessful(clientIP)
			IncrDNSStatsSuccessfulForPerView(clientIP, CLIENT)
			IncrDNSStatsTotalResponses(clientIP)
			ResponseForPerView(clientIP)
		}
	}
}
