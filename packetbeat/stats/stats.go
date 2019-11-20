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

package stats

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/beats/libbeat/logp"
)

type (
	Statistics struct {
		Start   time.Time `json:"start_time"`
		End     time.Time `json:"end_time"`
		Sniff   Sniff     `json:"sniff"`
		Decode  Decode    `json:"decode"`
		Publish Publish   `json:"publish"`
	}

	Sniff struct {
		TotalCaptured int64 `json:"total_captured"`
		Dropped       int64 `json:"dropped"`
	}

	Decode struct {
		DNS DNS `json:"dns"`
	}

	DNS struct {
		TotalReceived int64 `json:"total_received"`
		TCPReceived   int64 `json:"tcp_received"`
		UDPReceived   int64 `json:"udp_received"`
		Request       int64 `json:"request"`
		Response      int64 `json:"response"`
		Decoded       int64 `json:"decoded"`
		Dropped       int64 `json:"dropped"`
	}

	Publish struct {
		TotalReceived  int64 `json:"total_received"`
		KafkaPublished int64 `json:"kafka_published"`
		Dropped        int64 `json:"dropped"`
	}
)

var (
	glb *Statistics
	mux = &sync.RWMutex{}
)

func init() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		glb = &Statistics{Start: time.Now()}

		for {
			t := <-ticker.C
			mux.Lock()
			glb.End = t
			b, err := json.Marshal(glb)
			glb = &Statistics{Start: t}
			mux.Unlock()
			if err != nil {
				logp.Err("statistics: failed to marshal statistics report")
				continue
			}
			logp.Info("statistics: %s", b)
		}
	}()
}

func IncrSniffTotalCaptured() {
	atomic.AddInt64(&glb.Sniff.TotalCaptured, 1)
}
func IncrSniffDropped() {
	atomic.AddInt64(&glb.Sniff.Dropped, 1)
}

func IncrDNSReceived() {
	atomic.AddInt64(&glb.Decode.DNS.TotalReceived, 1)
}
func IncrDNSTCPReceived() {
	atomic.AddInt64(&glb.Decode.DNS.TCPReceived, 1)
}
func IncrDNSUDPReceived() {
	atomic.AddInt64(&glb.Decode.DNS.UDPReceived, 1)
}
func IncrDNSDecoded() {
	atomic.AddInt64(&glb.Decode.DNS.Decoded, 1)
}
func IncrDNSDropped() {
	atomic.AddInt64(&glb.Decode.DNS.Dropped, 1)
}
func IncrDNSRequest() {
	atomic.AddInt64(&glb.Decode.DNS.Request, 1)
}
func IncrDNSResponse() {
	atomic.AddInt64(&glb.Decode.DNS.Response, 1)
}

func IncrPublishReceived() {
	atomic.AddInt64(&glb.Publish.TotalReceived, 1)
}
func IncrKafkaPublished() {
	atomic.AddInt64(&glb.Publish.KafkaPublished, 1)
}
func IncrPublishDropped() {
	atomic.AddInt64(&glb.Publish.Dropped, 1)
}
