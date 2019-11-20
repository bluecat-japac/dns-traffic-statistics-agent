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

package model

import (
	"github.com/elastic/beats/libbeat/common"
	jsoniter "github.com/json-iterator/go"
)

var (
	json = jsoniter.ConfigCompatibleWithStandardLibrary
)

type MapStrWrapper struct {
	m common.MapStr

	encoded []byte
	err     error
}

func (m *MapStrWrapper) Encode() ([]byte, error) {
	m.ensureEncode()
	return m.encoded, m.err
}

func (m *MapStrWrapper) Length() int {
	m.ensureEncode()
	return len(m.encoded)
}

func (m *MapStrWrapper) ensureEncode() {
	if m.encoded == nil && m.err == nil {
		m.encoded, m.err = json.Marshal(m.m)
	}
}

type (
	RecordEncoder struct {
		r       *Record
		encoded []byte
		err     error
	}

	Record struct {
		Timestamp    string           `json:"timestamp"`
		Type         string           `json:"type, omitempty"`
		Transport    string           `json:"transport, omitempty"`
		Status       string           `json:"status, omitempty"`
		Notes        string           `json:"notes, omitempty"`
		BytesIn      int              `json:"bytes_in, omitempty"`
		BytesOut     int              `json:"bytes_out, omitempty"`
		ResponseTime float64          `json:"response_time, omitempty"`
		Method       string           `json:"method, omitempty"`
		Query        string           `json:"query, omitempty"`
		Resource     string           `json:"resource, omitempty"`
		Src          *common.Endpoint `json:"src, omitempty"`
		Dst          *common.Endpoint `json:"dst, omitempty"`
		DNS          *DNS             `json:"dns, omitempty"`
	}

	DNS struct {
		ID               uint16    `json:"id, omitempty"`
		OpCode           string    `json:"op_code, omitempty"`
		Flags            *Flags    `json:"flags, omitempty"`
		ResponseCode     string    `json:"response_code, omitempty"`
		Question         *Question `json:"question, omitempty"`
		Opt              *Opt      `json:"opt, omitempty"`
		AnswersCount     int       `json:"answers_count, omitempty"`
		AuthoritiesCount int       `json:"authorities_count, omitempty"`
		AdditionalsCount int       `json:"additionals_count, omitempty"`
		Answers          []*Answer `json:"answers, omitempty"`
		Authorities      []*Answer `json:"authorities, omitempty"`
		Additionals      []*Answer `json:"additionals, omitempty"`
	}

	Flags struct {
		AuthenticData      bool `json:"authentic_data, omitempty"`
		Authoritative      bool `json:"authoritative, omitempty"`
		CheckingDisabled   bool `json:"checking_disabled, omitempty"`
		RecursionAvailable bool `json:"recursion_available, omitempty"`
		RecursionDesired   bool `json:"recursion_desired, omitempty"`
		TruncatedResponse  bool `json:"truncated_response, omitempty"`
	}

	Question struct {
		Class       string `json:"class, omitempty"`
		EtldPlusOne string `json:"etld_plus_one, omitempty"`
		Name        string `json:"name, omitempty"`
		Type        string `json:"type, omitempty"`
	}

	Opt struct {
		Do       bool   `json:"do, omitempty"`
		ExtRcode string `json:"ext_rcode, omitempty"`
		UDPSize  uint16 `json:"udp_size, omitempty"`
		Version  string `json:"version, omitempty"`
		DAU      string `json:"dau, omitempty"`
		DHU      string `json:"dhu, omitempty"`
		LOCAL    string `json:"local, omitempty"`
		LLQ      string `json:"llq, omitempty"`
		N3U      string `json:"n3u, omitempty"`
		NSID     string `json:"nsid, omitempty"`
		SUBNET   string `json:"subnet, omitempty"`
		COOKIE   string `json:"cookie, omitempty"`
		UL       string `json:"ul, omitempty"`
	}

	Answer struct {
		Class string `json:"class, omitempty"`
		Data  string `json:"data, omitempty"`
		Name  string `json:"name, omitempty"`
		TTL   string `json:"ttl, omitempty"`
		Type  string `json:"type, omitempty"`

		Flags     string `json:"flags, omitempty"`
		Protocol  string `json:"protocol, omitempty"`
		Algorithm string `json:"algorithm, omitempty"`

		KeyTag     string `json:"key_tag, omitempty"`
		DigestType string `json:"digest_type, omitempty"`

		Preference uint16 `json:"preference, omitempty"`
		TypeBits   string `json:"type_bits, omitempty"`
		Hash       string `json:"hash, omitempty"`
		Iterations string `json:"iterations, omitempty"`
		Salt       string `json:"salt, omitempty"`

		TypeCovered string `json:"type_covered, omitempty"`
		Labels      string `json:"labels, omitempty"`
		OriginalTTL string `json:"original_ttl, omitempty"`

		Expiration string `json:"expiration, omitempty"`
		Inception  string `json:"inception, omitempty"`
		SignerName string `json:"signer_name, omitempty"`

		Rname   string `json:"rname, omitempty"`
		Serial  uint32 `json:"serial, omitempty"`
		Refresh uint32 `json:"refresh, omitempty"`
		Retry   uint32 `json:"retry, omitempty"`
		Expire  uint32 `json:"expire, omitempty"`
		Minimum uint32 `json:"minimum, omitempty"`

		Priority uint16 `json:"priority, omitempty"`
		Weight   uint16 `json:"weight, omitempty"`
		Port     uint16 `json:"port, omitempty"`
	}
)

func (re *RecordEncoder) Encode() ([]byte, error) {
	re.ensureEncode()
	return re.encoded, re.err
}

func (re *RecordEncoder) Length() int {
	re.ensureEncode()
	return len(re.encoded)
}

func (re *RecordEncoder) ensureEncode() {
	if re.encoded == nil && re.err == nil {
		re.encoded, re.err = json.Marshal(re.r)
	}
}
