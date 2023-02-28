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
	"fmt"
	"os"
	"time"
	"context"
	"syscall"
	"net/http"
	"os/signal"

	"github.com/elastic/beats/libbeat/logp"
)

func reqAnnouncementDeployFromBam(w http.ResponseWriter, req *http.Request) {
	logp.Debug("HTTP server", "Receive AnnouncementDeployFromBam request")
	ReloadNamedData(true)
}

func onLoadHTTPServer() {
	uriAnnouncementFromBam := fmt.Sprintf("/%v", UrlAnnouncementDeployFromBam)
	logp.Debug("onLoadHTTPServer", "Start Statistic HTTP server")
	// Receive request when postDeploy send request AnnouncementDeployFromBam
	http.HandleFunc(uriAnnouncementFromBam, reqAnnouncementDeployFromBam)
	s := &http.Server{Addr: StatHTTPServerAddr, Handler: nil}
	go start(s)
	stopCh, closeChFunc := createChannel()
	defer closeChFunc()
	<-stopCh
	shutdown(context.Background(), s)
}

func createChannel() (chan os.Signal, func()) {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	return stopCh, func() {
		close(stopCh)
	}
}

func start(server *http.Server) {
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logp.Err("onLoadHTTPServer", err)
		panic(err)
	}
}

func shutdown(ctx context.Context, server *http.Server) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}
	logp.Info("HTTP Packetbeat Server shutdowned gracefully")
}
