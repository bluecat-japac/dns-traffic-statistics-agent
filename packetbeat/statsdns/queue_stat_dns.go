// Copyright 2020 BlueCat Networks (USA) Inc. and its affiliates
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
	"time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/model"
)

type (
	// DNS data after decode
	QueryDNS struct {
		srcIP        string
		dstIP        string
		isDuplicated bool
	}
	RecursiveDNS struct {
		IP        string
		isSuccess bool
	}

	QueueStatDNS struct {
		isActive   bool
		isPopWait  bool
		queries    chan *QueryDNS
		recursives chan *RecursiveDNS
		records    chan *model.Record
	}
)

func NewQueryDNS(srcIP, dstIP string, isDuplicated bool) (queryDNS *QueryDNS) {
	queryDNS = &QueryDNS{
		srcIP:        srcIP,
		dstIP:        dstIP,
		isDuplicated: isDuplicated,
	}
	return
}

func NewRecursiveDNS(IP string, isSuccess bool) (recursiveDNS *RecursiveDNS) {
	recursiveDNS = &RecursiveDNS{
		IP:        IP,
		isSuccess: isSuccess,
	}
	return
}

func NewQueueStatDNS() (queue *QueueStatDNS) {
	queue = &QueueStatDNS{
		queries:    make(chan *QueryDNS),
		recursives: make(chan *RecursiveDNS),
		records:    make(chan *model.Record),
		isActive:   false,
		isPopWait:  true,
	}
	return
}

func (queue *QueueStatDNS) PushQueryDNS(queryDNS *QueryDNS) {
	if !queue.isActive {
		return
	}
	queue.queries <- queryDNS
}

func (queue *QueueStatDNS) PushRecordDNS(record *model.Record) {
	if !queue.isActive {
		return
	}
	queue.records <- record
}

func (queue *QueueStatDNS) PushRecursiveDNS(recursiveDNS *RecursiveDNS) {
	if !queue.isActive {
		return
	}
	queue.recursives <- recursiveDNS
}

func (queue *QueueStatDNS) PopStatDNS() {
	for queue.isActive {
		if queue.isPopWait {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		select {
		case query := <-queue.queries:
			if query == nil {
				continue
			}
			IncreaseQueryCounter(query.srcIP, query.dstIP, QUERY)
			IncreaseQueryCounterForPerView(query.srcIP, query.dstIP, QUERY)
			if query.isDuplicated {
				IncrDNSStatsDuplicated(query.srcIP)
				IncrDNSStatsDuplicatedForPerView(query.srcIP)
			}
		case recursive := <-queue.recursives:
			if recursive == nil {
				continue
			}
			IncrDNSStatsRecursive(recursive.IP)
			IncrDNSStatsRecursiveForPerView(recursive.IP)
			if recursive.isSuccess {
				IncrDNSStatsSuccessfulRecursive(recursive.IP)
				IncrDNSStatsSuccessfulRecursiveForPerView(recursive.IP)
			}
		case record := <-queue.records:
			if record == nil {
				continue
			}
			ReceivedMessage(record)
		}
	}
}

func (queue *QueueStatDNS) Stop() {
	logp.Info("QueueStatDNS Stop")
	queue.isActive = false
	close(queue.queries)
	close(queue.recursives)
	close(queue.records)
}
