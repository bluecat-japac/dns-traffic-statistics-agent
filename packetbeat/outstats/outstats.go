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

package outstats

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"sync"
	// "time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/config_statistics"
)

var (
	client    = &http.Client{}
	cacheData = make([]string, 0)
	mutex     = &sync.RWMutex{}
)

func init() {
	// go func() {
	// 	logp.Info("Interval Clear Out Statis Cache %v", config_statistics.ConfigStat.IntervalClearOutStatisCache)
	// 	//Prevent Statistic config file hasn't already loaded
	// 	for config_statistics.ConfigStat.IntervalClearOutStatisCache == 0 {
	// 		logp.Info("Interval Clear Out Statis Cache %v", config_statistics.ConfigStat.IntervalClearOutStatisCache)
	// 	}
	// 	ticker := time.NewTicker(time.Duration(config_statistics.ConfigStat.IntervalClearOutStatisCache) * time.Second)
	// 	for {
	// 		t := <-ticker.C
	// 		mutex.Lock()
	// 		logp.Info("Clear first element in cache Data %s", t)
	// 		popElementInCache()
	// 		logp.Debug("outstats", "CACHED DATA %v", cacheData)
	// 		mutex.Unlock()
	// 	}
	// }()
}

func popElementInCache() {
	if len(cacheData) > 0 {
		cacheData = append(cacheData[:0], cacheData[1:]...)
	}
}

func pushElementInCache(data string) {
	cacheData = append(cacheData, data)
}

func sendData(data string) (*http.Response, error) {
	var url = config_statistics.ConfigStat.StatisticsDestination
	var jsonStr = []byte(data)
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	return resp, err
}

func printHttpBodyResult(resp *http.Response) {
	body, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(body)
	logp.Info("Out Statistics Response %v", bodyString)
}

func resendData() {
	go func() {
		for len(cacheData) > 0 {
			resp, err := sendData(cacheData[0])
			if err != nil {
				break
			}
			popElementInCache()
			logp.Info("Out Statistics From Cached")
			printHttpBodyResult(resp)
		}
	}()
}

func PublishToSNMPAgent(data string) {
	resp, err := sendData(data)
	if err != nil {
		// pushElementInCache(data)
		// logp.Debug("outstats", "CACHED DATA %v", cacheData)
		logp.Err("outstats: Cannot send data to agent")
		// logp.Error(str(err)
		return
	} else {
		printHttpBodyResult(resp)
		// resendData()
	}

	defer resp.Body.Close()
}
