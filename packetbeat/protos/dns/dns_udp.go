// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package dns

import (
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	//Bluecat
	//"github.com/elastic/beats/packetbeat/stats"
)

// Only EDNS packets should have their size beyond this value
const maxDNSPacketSize = (1 << 9) // 512 (bytes)

type BytesEncoder []byte

func (b BytesEncoder) Encode() ([]byte, error) {
	return b, nil
}

func (b BytesEncoder) Length() int {
	return len(b)
}

func (dns *dnsPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("Dns ParseUdp")
	packetSize := len(pkt.Payload)
	// logp.Info("Received a packet UDP")
	debugf("Parse UDP OF DNS Packet")
	//Bluecat Disable Old Statistic
	//stats.IncrDNSUDPReceived()
	//stats.IncrDNSReceived()

	debugf("Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), packetSize)

	// [Bluecat]: Disable DNS decoding
	//  Push raw data to Kafka directly, no decoding involved]

	// dkduy: append [ip size] + [ip address] to raw packet
	// var customizeDnsRaw []byte

	// ip_size := len(pkt.Tuple.SrcIP)
	// customizeDnsRaw = []byte(string(ip_size) + string(pkt.Tuple.SrcIP) + string(pkt.Payload))

	// fmt.Println(ip_size, pkt.Tuple.SrcIP, customizeDnsRaw)

	// dns.kafkaProd.Input() <- &sarama.ProducerMessage{
	// 	Timestamp: time.Now(),
	// 	Topic:     dns.kafkaConf.Topic,
	// 	//Value:     BytesEncoder(pkt.Payload),
	// 	Value: BytesEncoder(customizeDnsRaw),
	// }
	// stats.IncrKafkaPublished()
	//debugf("Parse UDP OF DNS Packet RETURN NOT DECODED JUST RAW")
	//return

	//[Bluecat]
	//Drop packet if it's IP doesn't contain in Valid Array IP Range That has been configured in statistics_config.json

	// logp.Info("%s", pkt.Tuple.SrcIP.String())
	// logp.Info("%v", statsdns.IPsNet)
	// logp.Info("%t", utils.CheckIPInRanges(pkt.Tuple.SrcIP.String(), statsdns.IPsNet))

	// if !utils.CheckIPInRanges(pkt.Tuple.SrcIP.String(), statsdns.IPsNet) {
	// 	return
	// }

	dnsPkt, err := decodeDNSData(transportUDP, pkt.Payload)

	if err != nil {
		//Bluecat
		// Need to update the metric for the client
		handleErrorMsg(pkt.Tuple.SrcIP.String(), pkt.Tuple.DstIP.String(), transportUDP, pkt.Payload, pkt.Tuple)
		// This means that malformed requests or responses are being sent or
		// that someone is attempting to the DNS port for non-DNS traffic. Both
		// are issues that a monitoring system should report.
		debugf("%s", err.Error())

		return
	}

	///Bluecat Disable Old Statistic
	//stats.IncrDNSDecoded()

	dnsTuple := dnsTupleFromIPPort(&pkt.Tuple, transportUDP, dnsPkt.Id)
	dnsMsg := &dnsMessage{
		ts:           pkt.Ts,
		tuple:        pkt.Tuple,
		cmdlineTuple: procs.ProcWatcher.FindProcessesTupleUDP(&pkt.Tuple),
		data:         dnsPkt,
		length:       packetSize,
	}

	if dnsMsg.data.Response {
		///Bluecat Disable Old Statistic
		//stats.IncrDNSResponse()
		dns.receivedDNSResponse(&dnsTuple, dnsMsg)
	} else /* Query */ {
		///Bluecat Disable Old Statistic
		//stats.IncrDNSRequest()
		dns.receivedDNSRequest(&dnsTuple, dnsMsg)
	}
}
