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
	"github.com/elastic/beats/libbeat/common/kafka"
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
	"time"
)

type dnsConfig struct {
	config.ProtocolCommon `config:",inline"`
	IncludeAuthorities    bool `config:"include_authorities"`
	IncludeAdditionals    bool `config:"include_additionals"`

	// [Bluecat]
	DropDecodedPacket bool `config:"drop_decoded_packet"`

	Kafka KafkaConfig `json:"kafka"`
}

type (
	KafkaConfig struct {
		Hosts []string `config:"hosts"               validate:"required"`
		Topic string   `config:"topic"               validate:"required"`
		// TLS              *tlscommon.Config         `config:"ssl"`
		Timeout time.Duration `config:"timeout"             validate:"min=1"`
		// Metadata         MetaConfig                `config:"metadata"`
		// Key              *fmtstr.EventFormatString `config:"key"`
		// Partition        map[string]*common.Config `config:"partition"`
		KeepAlive            time.Duration `config:"keep_alive"          validate:"min=0"`
		RequiredACKs         *int          `config:"required_acks"       validate:"min=-1"`
		BrokerTimeout        time.Duration `config:"broker_timeout"      validate:"min=1"`
		Compression          string        `config:"compression"`
		CompressionLevel     int           `config:"compression_level"`
		Version              kafka.Version `config:"version"`
		BulkMaxSize          int           `config:"bulk_max_size"`
		MaxRetries           int           `config:"max_retries"         validate:"min=0"`
		RetryBackoffDuration time.Duration `config:"retry_backoff_duration"`
		ClientID             string        `config:"client_id"`
		ChanBufferSize       int           `config:"channel_buffer_size" validate:"min=1"`
		Username             string        `config:"username"`
		Password             string        `config:"password"`
		// Codec            codec.Config              `config:"codec"`
		FlushFrequency  time.Duration `config:"flush_frequency"`
		FlushMaxBytes   int           `config:"flush_max_bytes"`
		MaxMessageBytes int           `config:"max_message_bytes"   validate:"min=1"`
		MaxMessages     int           `config:"max_messages"   validate:"min=1"`
		Messages        int           `config:"messages"   validate:"min=1"`
	}

	MetaConfig struct {
		Retry       MetaRetryConfig `config:"retry"`
		RefreshFreq time.Duration   `config:"refresh_frequency" validate:"min=0"`
	}

	MetaRetryConfig struct {
		Max     int           `config:"max"     validate:"min=0"`
		Backoff time.Duration `config:"backoff" validate:"min=0"`
	}
)

var (
	defaultConfig = dnsConfig{
		ProtocolCommon: config.ProtocolCommon{
			TransactionTimeout: protos.DefaultTransactionExpiration,
		},
	}
)
